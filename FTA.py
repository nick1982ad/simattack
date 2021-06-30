import json
import networkx as nx
from pyvis.network import Network

#from collections import OrderedDict



def add_FT_nodes(tree, parent, child):
    d_type = {
        'basic': 0,
        'or': 0,
        'and': 1
    }
    c_node = child['name']
    #добавляем новую вершину дерева
    tree.add_node(c_node, impact=child.get('impact', 0))
    #смотрим на тип вершины и переводим в потерю
    if child['node_type'] == 'k_from_n':
        #мажоритарное или - потеря вершины = k - 1
        tree.nodes[c_node]['loss'] = int(child['k']) - 1
    else:
        #в прочих случаях берем по словарю (или - 0, и - 1, по умолчанию - 0)
        tree.nodes[c_node]['loss'] = d_type.get(child['node_type'], 0)
    #если  не корень (parent отличается от None)
    #добавляем ребро от потомка к предку (для последующего поиска потока)
    #у всех ребер пропускная способность = 1
    if parent:
        tree.add_edge(c_node, parent, capacity=1)
    #проходим рекурентно по всем детям
    for c in child.get('childs', []):
        #рекуррентно вызываем создание узлов
        tree = add_FT_nodes(tree, c_node, c)
    return tree
#чтение файла с json описанием дерева неисправностей
jf = open('FT.json','r',encoding='utf-8')
FT_j = json.load(jf)

FT = nx.DiGraph()
#if len(FT_j) > 1:
#    print('Неверное дерево неисправностей: более одного корня!')
#    exit(1)
FT = add_FT_nodes(FT, None, FT_j)

nt = Network('750','750px', directed=True, notebook=False)

# populates the nodes and edges data structures
nt.from_nx(FT)
#nt.show_buttons(filter_=['edges'])
#nt.set_options("""
#var options = {
#  "physics": {
#    "repulsion": {
#      "springLength": 325,
#      "springConstant": 0
#    },
#    "minVelocity": 0.75,
#    "solver": "repulsion"
#  }
#}
#"""
#)
nt.show('FT.html')
