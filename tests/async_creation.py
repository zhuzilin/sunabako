"""CPU checks for native asynchronous RPCs and sandbox creation cleanup."""
import asyncio
import array
import contextlib
import json
import os
import random
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunabako import AsyncSandbox, Cluster, Node
from sunabako.client import SandboxError


class AsyncCreationTests(unittest.IsolatedAsyncioTestCase):
    async def test_more_than_32_cold_creates_can_progress_without_blocking_rpc(self):
        release, all_started = asyncio.Event(), asyncio.Event()
        started = 0
        async def call(node, *args, **kwargs):
            nonlocal started
            if args[0] == 'create':
                started += 1
                if started == 96:
                    all_started.set()
                await release.wait()
            return {'exit_code': 0, 'stdout': 'ok', 'stderr': ''}
        with patch.object(Node, 'call_async', call), patch('asyncio.to_thread', side_effect=AssertionError('thread pool used')):
            tasks = [asyncio.create_task(AsyncSandbox.create(sandbox_id=f'test-{i}')) for i in range(96)]
            try:
                await asyncio.wait_for(all_started.wait(), timeout=2)
                existing = await AsyncSandbox.connect('existing', node=Node())
                self.assertEqual((await existing.commands.run('true')).stdout, 'ok')
            finally:
                release.set()
                await asyncio.gather(*tasks)

    async def test_repeated_cancellation_waits_for_owned_remote_cleanup(self):
        started, transport_closed, cleaning, release = (asyncio.Event() for _ in range(4))
        calls = []
        async def call(node, *args, **kwargs):
            calls.append((args, kwargs))
            if args[0] == 'create':
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    transport_closed.set()
            if args[0] == 'cancel-create':
                self.assertTrue(transport_closed.is_set())
                cleaning.set()
                await release.wait()
                return {'cancelled': True, 'deleted': True}
            raise AssertionError(args)
        with patch.object(Node, 'call_async', call):
            task = asyncio.create_task(AsyncSandbox.create())
            await started.wait()
            task.cancel()
            await cleaning.wait()
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual([c[0][0] for c in calls], ['create', 'cancel-create'])
        self.assertEqual(calls[0][0][2], '--token')
        self.assertEqual(calls[0][0][3], calls[1][0][2])
        self.assertEqual(calls[0][1]['data']['id'], calls[1][0][1])

    async def test_capacity_rejection_falls_back_but_transport_failure_does_not(self):
        for error, expected in [('node memory admission exhausted', ['first', 'second']), ('Transport timed out', ['first'])]:
            calls = []
            async def call(node, *args, **kwargs):
                if args[0] == 'capacity':
                    return {'memory_reserved': 0 if node.name == 'first' else 1, 'config': {'memory_capacity_bytes': 1024}}
                if args[0] == 'cancel-create':
                    return {'cancelled': True, 'deleted': True}
                calls.append(node.name)
                if node.name == 'first':
                    raise SandboxError(error)
                return {}
            with patch.object(Node, 'call_async', call), patch('sunabako.client.random.expovariate', side_effect=[0, 1]):
                task = AsyncSandbox.create(cluster=Cluster([Node(name='first'), Node(name='second')]))
                if error.startswith('Transport'):
                    with self.assertRaises(SandboxError):
                        await task
                else:
                    self.assertEqual((await task).node.name, 'second')
            self.assertEqual(calls, expected)

    async def test_stale_nearly_equal_capacities_do_not_concentrate_a_burst(self):
        assigned = []
        async def call(node, *args, **kwargs):
            if args[0] == 'capacity':
                return {'memory_reserved': 0 if node.name == 'first' else 64 << 20,
                        'config': {'memory_capacity_bytes': 1 << 30}}
            assigned.append(node.name)
            return {}
        rng = random.Random(1234)
        cluster = Cluster([Node(name='first'), Node(name='second')])
        with patch.object(Node, 'call_async', call), patch('sunabako.client.random.expovariate', rng.expovariate):
            await asyncio.gather(*(AsyncSandbox.create(cluster=cluster) for _ in range(128)))
        # All callers see the same slightly stale snapshot; neither node should
        # receive the whole burst before it can publish its first reservation.
        self.assertGreater(assigned.count('first'), 32)
        self.assertGreater(assigned.count('second'), 32)

    async def test_lost_creation_reply_cancels_only_its_request(self):
        calls = []
        async def call(node, *args, **kwargs):
            calls.append((args, kwargs))
            if args[0] == 'create':
                raise SandboxError('Transport timed out after remote creation')
            self.assertEqual(args[0], 'cancel-create')
            return {'cancelled': True, 'deleted': True, 'cleanup_pending': True}
        with patch.object(Node, 'call_async', call):
            with self.assertRaisesRegex(SandboxError, 'Transport timed out'):
                await AsyncSandbox.create(sandbox_id='owned')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][0], ('cancel-create', 'owned', calls[0][0][3]))

    async def test_unconfirmed_cleanup_prevents_capacity_fallback(self):
        calls = []
        async def call(node, *args, **kwargs):
            if args[0] == 'capacity':
                return {'memory_reserved': 0, 'config': {'memory_capacity_bytes': 1024}}
            calls.append((node.name, args[0]))
            if args[0] == 'create':
                raise SandboxError('memory admission exhausted')
            return {}
        with patch.object(Node, 'call_async', call), patch('sunabako.client.random.expovariate', side_effect=[0, 1]):
            with self.assertRaisesRegex(SandboxError, 'could not confirm creation cleanup'):
                await AsyncSandbox.create(cluster=Cluster([Node(name='first'), Node(name='second')]))
        self.assertEqual(calls, [('first', 'create'), ('first', 'cancel-create')])

    async def test_real_subprocess_rpc_and_timeout_reaping(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / 'fake-node'
            binary.write_text('''#!/usr/bin/env python3
import json,sys,time,os
from pathlib import Path
state=Path(sys.argv[2])
if sys.argv[3] == 'cancel-create':
 print(json.dumps({'cancelled':True,'deleted':True}))
 sys.exit(0)
if sys.argv[3] in {'slow', 'create'}:
 (state/'pid').write_text(str(os.getpid()))
 time.sleep(30)
print(json.dumps({'input':json.load(sys.stdin)}))
''')
            binary.chmod(0o700)
            node = Node(binary=str(binary), state_dir=temp)
            with patch('asyncio.to_thread', side_effect=AssertionError('thread pool used')):
                result = await node.call_async('echo', data={'text': 'x' * (1 << 20)})
                self.assertEqual(len(result['input']['text']), 1 << 20)
                with self.assertRaisesRegex(SandboxError, 'Transport timed out'):
                    await node.call_async('slow', data={}, timeout=0.5)
                with self.assertRaisesRegex(SandboxError, 'Transport timed out'):
                    await AsyncSandbox.create(node=node, create_timeout=0.2)
            pid = int((root / 'pid').read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    async def test_invalid_guest_user_is_rejected_before_request(self):
        from sunabako.client import Sandbox
        sandbox = AsyncSandbox(Sandbox('test', node=Node()))
        with patch.object(Node, 'call_async', side_effect=AssertionError('sent request')):
            with self.assertRaises(ValueError):
                await sandbox.commands.run('true', user='root;exit')
            with self.assertRaises(ValueError):
                await sandbox.files.write('/tmp/x', b'', user='root;exit')

    async def test_timeout_and_cancellation_close_pipes_retained_by_another_process(self):
        # An SSH multiplexing master retains a channel's stderr descriptor even
        # after its client exits. Simulate descriptor passing without SSH, and
        # keep the receiver alive independently of the timed-out subprocess.
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                binary = root / 'fake-node'
                binary.write_text('''#!/usr/bin/env python3
import array,os,socket,sys,time
from pathlib import Path
state=Path(sys.argv[2])
with socket.socket(socket.AF_UNIX) as channel:
 channel.connect(str(state/'master.sock'))
 channel.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [2]))])
(state/'pid').write_text(str(os.getpid()))
time.sleep(30)
''')
                binary.chmod(0o700)
                held_fd = None
                with socket.socket(socket.AF_UNIX) as server:
                    server.bind(str(root / 'master.sock'))
                    server.listen(1)
                    node = Node(binary=str(binary), state_dir=temp)
                    task = asyncio.create_task(node.call_async('slow', timeout=None if cancelled else 0.5))
                    try:
                        deadline = asyncio.get_running_loop().time() + 2
                        while not (root / 'pid').exists():
                            self.assertLess(asyncio.get_running_loop().time(), deadline, 'transport did not start')
                            await asyncio.sleep(0.01)
                        connection, _ = server.accept()
                        with connection:
                            _, descriptors, _, _ = connection.recvmsg(1, socket.CMSG_SPACE(array.array('i').itemsize))
                        received = array.array('i')
                        received.frombytes(descriptors[0][2][:received.itemsize])
                        held_fd = received[0]
                        if cancelled:
                            task.cancel()
                        done, _ = await asyncio.wait([task], timeout=1.5)
                        self.assertIn(task, done, 'cleanup waited for a pipe held by the shared transport')
                        expected = asyncio.CancelledError if cancelled else SandboxError
                        with self.assertRaises(expected):
                            await task
                        # Closing the RPC's local reader must not close or kill
                        # the independently owned descriptor holder.
                        os.fstat(held_fd)
                        with self.assertRaises(BrokenPipeError):
                            os.write(held_fd, b'still-owned')
                        with self.assertRaises(ProcessLookupError):
                            os.kill(int((root / 'pid').read_text()), 0)
                    finally:
                        if held_fd is not None:
                            os.close(held_fd)
                        if not task.done():
                            task.cancel()
                        with contextlib.suppress(SandboxError, asyncio.CancelledError):
                            await asyncio.wait_for(task, timeout=2)

    async def test_invalid_creation_deadline_is_rejected_before_request(self):
        from sunabako.client import Sandbox
        with patch.object(Node, 'call_async', side_effect=AssertionError('sent request')), \
             patch.object(Node, 'call', side_effect=AssertionError('sent request')):
            for timeout in [0, -1, float('nan'), float('inf')]:
                with self.assertRaises(ValueError):
                    await AsyncSandbox.create(create_timeout=timeout)
                with self.assertRaises(ValueError):
                    Sandbox.create(create_timeout=timeout)


if __name__ == '__main__':
    unittest.main()
