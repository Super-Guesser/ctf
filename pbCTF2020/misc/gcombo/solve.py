#!/usr/python2
from collections import defaultdict
from parsed import z

class Graph:
    def __init__(self):
        self.graph = defaultdict(list)
 
    def addEdge(self,u,v):
        self.graph[u].append(v)
 
    def bfs(self, s, e):
        queue = []
        queue.append([s])
 
        while queue:
            s = queue.pop(0)
            node = s[-1]

            if node == e:
                return s
            
            for adjacent in self.graph.get(node, []):
                new_path = list(s)
                new_path.append(adjacent)
                queue.append(new_path)

edges = set()
d = dict()

for i in range(20):
    parent = z[(i*2) + 1][0]
    for j in range(10):
        try:
            d[z[(i*2)+2][4][0][1][j][2]] = int(z[(i*2)+2][4][0][1][j][0])
            edges.add((parent, z[(i*2)+2][4][0][1][j][2]))
        except:
            pass

g = Graph()
for i, j in edges:
    g.addEdge(i,j)

path = g.bfs(1114266997, 751651474)
print 5,
for i in path[1:]:
    print d[i],
