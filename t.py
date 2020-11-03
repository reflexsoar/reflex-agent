from multiprocessing import Process, Queue

queue = Queue()

def f(queue):
    while not queue.empty():
        x = queue.get()
        print(x*2)

def do_work():
    processes = [Process(target=f, args=(queue,)) for _ in range(2)]
    for p in processes:
        p.start()

    for p in processes:
        p.join()

if __name__ == "__main__":
    items = [1,2,3,4,5,6,7,8,9,10]
    [queue.put(i) for i in items]
    do_work()    