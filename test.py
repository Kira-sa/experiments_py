import time
import queue
import collections

q = collections.deque()
t0 = time.perf_counter()
for i in range(100000):
    q.append(1)
for i in range(100000):
    q.popleft()
print ('deque {}'.format(time.perf_counter() - t0))

q = queue.Queue()
t0 = time.perf_counter()
for i in range(100000):
    q.put(1)
for i in range(100000):
    q.get()
print ('Queue {}'.format(time.perf_counter() - t0))