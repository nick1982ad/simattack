import numpy as np
import networkx as nx
import time
# from pyvis.network import Network
import pandas as pd
from collections import OrderedDict
import json
import random

weight = np.array([0, 1, np.inf])
rng = np.random.default_rng()

import os
os.chdir('D:\Google\work\ПОАР\Model\simattack')
input_data = 'example1'
vulner = pd.read_excel('.\\' + input_data + '\\data.xlsx', sheet_name='Vulnerabilities', index_col='id')
counter_m = pd.read_excel('.\\' + input_data + '\\data.xlsx', sheet_name='C-Measures', index_col='id')
prevent_matrix = pd.read_excel('.\\' + input_data + '\\data.xlsx', sheet_name='Measures-Vuln-P', index_col='id',
                               dtype=object)
detect_matrix = pd.read_excel('.\\' + input_data + '\\data.xlsx', sheet_name='Measures-Vuln-D', index_col='id',
                              dtype=object)

t_begin = time.time()
G = nx.generators.random_graphs.dense_gnm_random_graph(15000, 20000)
t_end = time.time()


print(t_end - t_begin)

for e in list(G.edges):
    G.edges[e]['weight'] = rng.choice(weight, size=1, p=[0.4, 0.5, 0.1])

Link_MG = G.copy()


vuln_matrix_np = np.random.choice([0, 1], size=(len(vulner.index), 15000), p=[0.9, 0.1])

vuln_matrix = pd.DataFrame(data=vuln_matrix_np, index=vulner.index)


vulner.loc[vulner.AV == 'P', 'AV'] = -np.inf
vulner.loc[vulner.AV == 'L', 'AV'] = 0
vulner.loc[vulner.AV == 'A', 'AV'] = 1
vulner.loc[vulner.AV == 'N', 'AV'] = 2

vulner.loc[vulner.PR == 'N', 'PR'] = 0
vulner.loc[vulner.PR == 'L', 'PR'] = 1
vulner.loc[vulner.PR == 'H', 'PR'] = 2

vulner.loc[vulner['s.AV'] == 'P', 's.AV'] = np.inf
vulner.loc[vulner['s.AV'] == 'L', 's.AV'] = 0
vulner.loc[vulner['s.AV'] == 'A', 's.AV'] = 1
vulner.loc[vulner['s.AV'] == 'N', 's.AV'] = 2

vulner.loc[vulner['s.PR'] == 'N', 's.PR'] = 0
vulner.loc[vulner['s.PR'] == 'L', 's.PR'] = 1
vulner.loc[vulner['s.PR'] == 'H', 's.PR'] = 2


cont_counter_m = counter_m[counter_m['Период'] == 0]
k = 1


for (vuln, prob) in prevent_matrix.iteritems():
    vulner.at[vuln, 'P_v'] = (1 - prob[cont_counter_m.index]).prod() * k * vulner.at[vuln, 'Prob']
for (vuln, prob) in detect_matrix.iteritems():
    vulner.at[vuln, 'P_d'] = 1 - (1 - prob[cont_counter_m.index]).prod()


# %%

# CtxA
def get_asset(df, col_name, val):
    return df[df[col_name] == val]


# CtxN
def get_all_assets(df, col_name):
    return df[col_name].unique()


# Pr(a)
def get_pr_asset(df, col_name, val, pr_col_name):
    sub_df = df[df[col_name] == val]
    if len(sub_df):
        return df[df[col_name] == val][pr_col_name].max()
    else:
        return 0


# PhAdj(a)
def phys_adj(G, node):
    return [n for n in G.neighbors(node) if G.edges[node, n]['weight'] == np.inf]


# %%

# задаем контекст
cols = ['a_id', 'AV', 'PR', 'I']
Ctx_0 = pd.DataFrame(columns=cols)
# ___________________контекст для example1___________________________________________
Ctx_0 = Ctx_0.append({'a_id': 4, 'AV': 0, 'PR': 0, 'I': 0}, ignore_index=True)
Ctx_0 = Ctx_0.append({'a_id': 9, 'AV': np.inf, 'PR': 0, 'I': 0}, ignore_index=True)
# ___________________контекст для minimal___________________________________________
# Ctx_0 = Ctx_0.append({'a_id' : 0, 'AV' : 0, 'PR' : 0, 'I' : 0}, ignore_index = True)
# Ctx_0 = Ctx_0.append({'a_id' : 1, 'AV' : 0, 'PR' : 0, 'I' : 0}, ignore_index = True)

# %%

G_dash = nx.MultiDiGraph()

# %%

# инциализация графа начальным контекстом
G_dash.add_nodes_from(list(Ctx_0.index))
# nx.set_node_attributes(G_dash, Ctx_0.to_dict(orient='index'))
# вспомогательный DataFrame для более удобных выборок врешин (возможно не надо писать атрибуты в граф)
A_df = pd.DataFrame(Ctx_0)

# инициализация переменного контекста
Ctx = pd.DataFrame(Ctx_0)

# %%

t_begin = time.time()
# Основной цикл
while len(Ctx.index):

    # извлечь вершину из текущего контекста
    a_begin = Ctx.iloc[-1]
    Ctx = Ctx.drop([a_begin.name])
    if a_begin['AV'] == np.inf:
        a_end_list = phys_adj(Link_MG, a_begin['a_id'])
        a_end_list.append(a_begin['a_id'])
        for a_end_id in a_end_list:
            a_name = a_end_id
            pr_a = get_pr_asset(A_df, 'a_id', a_end_id, 'PR')
            v_index = list(vuln_matrix[vuln_matrix[a_name] == 1].index)
            v_sub_df = vulner.loc[v_index]
            v_sub_df = v_sub_df[v_sub_df.PR <= pr_a]
            for v_id, v_data in v_sub_df.iterrows():
                str_search = "(a_id == {a_id}) & (AV == {v_AV}) & (PR == {v_PR}) & (I == {I})".format(
                    a_id=a_end_id,
                    v_AV=v_data['s.AV'],
                    v_PR=v_data['s.PR'],
                    I=v_data['Imp']
                )
                a_ex_ind = A_df.query(str_search).index
                # не найдена такая вершина в графе
                if len(a_ex_ind) == 0:
                    a_dict = {'a_id': a_end_id, 'AV': v_data['s.AV'], 'PR': v_data['s.PR'], 'I': v_data['Imp']}
                    A_df = A_df.append(a_dict, ignore_index=True)
                    a_series = A_df.iloc[-1]
                    a_ex_ind = a_series.name
                    G_dash.add_node(int(a_ex_ind))
                    if a_series['I'] == 0:
                        Ctx = Ctx.append(A_df.iloc[a_ex_ind])
                else:
                    a_ex_ind = a_ex_ind[0]
                G_dash.add_edge(int(a_begin.name), int(a_ex_ind), label=v_id)
    else:
        for a_end_id in Link_MG.nodes():
            if nx.algorithms.shortest_paths.generic.has_path(Link_MG, source=a_begin['a_id'], target=a_end_id):
                d = nx.shortest_path_length(Link_MG, source=a_begin['a_id'], target=a_end_id, weight='weight')
            else:
                d = np.inf
            a_name = a_end_id
            pr_a = get_pr_asset(A_df, 'a_id', a_end_id, 'PR')
            v_index = list(vuln_matrix[vuln_matrix[a_name] == 1].index)
            if len(v_index):
                v_sub_df = vulner.loc[v_index]
                v_sub_df = v_sub_df[(v_sub_df.PR <= pr_a) & (v_sub_df.AV >= a_begin['AV'] + d)]
                for v_id, v_data in v_sub_df.iterrows():
                    str_search = "(a_id == {a_id}) & (AV == {v_AV}) & (PR == {v_PR}) & (I == {I})".format(
                        a_id=a_end_id,
                        v_AV=v_data['s.AV'],
                        v_PR=v_data['s.PR'],
                        I=v_data['Imp']
                    )
                    a_ex_ind = A_df.query(str_search).index
                    # не найдена такая вершина в графе
                    if len(a_ex_ind) == 0:
                        a_dict = {'a_id': a_end_id, 'AV': v_data['s.AV'], 'PR': v_data['s.PR'], 'I': v_data['Imp']}
                        A_df = A_df.append(a_dict, ignore_index=True)
                        a_series = A_df.iloc[-1]
                        a_ex_ind = a_series.name
                        G_dash.add_node(int(a_ex_ind))
                        if a_series['I'] == 0:
                            Ctx = Ctx.append(A_df.iloc[a_ex_ind])
                    else:
                        a_ex_ind = a_ex_ind[0]
                    G_dash.add_edge(int(a_begin.name), int(a_ex_ind), label=v_id)
t_end = time.time()

# %%

print(t_end - t_begin)

# %%


