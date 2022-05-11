import json
#import os
import pandas as pd
import random
import numpy as np
import copy


time_scale = {
    'minute': 1,
    'hour': 60,
    'day': 60 * 24,
    'month': 60 * 24 * 30,
    'year': 60 * 24 * 365
}


def init_json(path):
    f_json = open(path, 'r', encoding='utf-8-sig')
    data_j = json.load(f_json)
    return data_j

def add_segment(s):
    segment = {'id': str(s['Parent.originalId']), 'kind': 'local'}
    s['segments'] = [segment]
    return s

def add_self_local(s):
    loc_segment = {'id': s['originalId'], 'kind': 'local'}
    s['segments'].append(loc_segment)
    return s

def get_sub_id(data_j,sub_name):
    subsystems_df = pd.json_normalize(data_j['subsystems'])
    sub_id = list(subsystems_df.query('caption in @sub_name')['id'])
    return sub_id

def adjust_time(s, prefix):
    s[prefix + '.interval'] = s[prefix + '.interval'] * time_scale.get(s[prefix + '.kind'],0)
    return s


def get_assets_df(data_j, sub_id):
    assets_df = pd.json_normalize(data_j['nodes'])
    assets_df = assets_df.drop(['softwareDefence', 'software'], axis=1)
    sec_assets = pd.json_normalize(data_j['nodes'], record_path='softwareDefence', max_level=0, meta=['originalId'],
                                   meta_prefix='Parent.', errors='ignore')
    if not(sec_assets.empty):
        for idx, row in sec_assets.iterrows():
            if row['protectionMeasure']:
                assets_df.query('originalId == @row["Parent.originalId"]').iloc[0]['protectionMeasures'].extend(
                    [row['protectionMeasure']])
        sec_assets = sec_assets.drop(['protectionMeasure'], axis=1)
    app_assets = pd.json_normalize(data_j['nodes'], record_path='software', max_level=0, meta=['originalId'],
                                   meta_prefix='Parent.', errors='ignore')
    sec_assets = pd.concat([sec_assets, app_assets], ignore_index=True)
    sec_assets['segments'] = None
    sec_assets = sec_assets.apply(add_segment, axis=1)
    sec_assets = sec_assets.drop(['Parent.originalId'], axis=1)
    # нормализация данных
    values = {'segments': [],
              'vulnerabilities': [],
              'protectionMeasures': [],
              'isValuable': False,
              'subsystemId': -1,
              'code': -1,
              'class': '',
              'kks': '',
              'originalId': '',
              'id': -1,
              'caption': 0}

    assets_df = assets_df.apply(lambda s: s.fillna({i: copy.copy(values[s.name]) for i in s.index}))
    assets_df = assets_df.apply(add_self_local, axis=1)
    assets_df = pd.concat([assets_df, sec_assets, ], ignore_index=True)
    #добавление edges (каналов)
    edge_df = pd.json_normalize(data_j['edges'])
    edge_df = edge_df.query('subsystemId == @sub_id')
    edge_df['segments'] = None
    edge_df = edge_df.apply(lambda s: s.fillna({i: copy.copy(values.get(s.name,'')) for i in s.index}))

    for idx, row in edge_df.iterrows():
        segment_name = {'id': row['originalId'], 'kind': 'physical'}
        row['segments']  = row['segments'].append(segment_name)
        # нашел источник - добавляю сегмент
        if not (assets_df.query("id == @row['sourceNodeId']").empty):
            assets_df.query("id == @row['sourceNodeId']").iloc[-1]['segments'] = \
            assets_df.query("id == @row['sourceNodeId']").iloc[-1]['segments'].append(segment_name)
        # нашел назначение - добавляю сегмент
        if not (assets_df.query("id == @row['targetNodeId']").empty):
            assets_df.query("id == @row['targetNodeId']").iloc[-1]['segments'] = \
            assets_df.query("id == @row['targetNodeId']").iloc[-1]['segments'].append(segment_name)
    edge_df = edge_df.drop(['sourceNodeId','targetNodeId'], axis=1)
    assets_df = pd.concat([assets_df, edge_df], ignore_index=True)

    assets_filtered = assets_df.query('subsystemId in @sub_id')


    #segments_df = pd.json_normalize(assets_filtered.iloc[0]['segments'])
    #segments_df['id'] = segments_df['id'].astype(str) + segments_df['kind']
    # набираем информацию из активов и формируем нужный DF
    A_df = pd.DataFrame()
    for asset_id in list(assets_filtered.id):
        #    assets_df.query('id == @asset_id').iloc[-1]['protectionMeasures']
        asset_s = assets_df.query('id == @asset_id').iloc[-1]
        TTR = pd.json_normalize(asset_s['protectionMeasures'], record_path='vulnerabilities')
        min_TTR = 0
        if 'recoveryTime.interval' in TTR:
            TTR = TTR.apply(adjust_time, axis=1, prefix = 'recoveryTime')
            min_TTR = TTR['recoveryTime.interval'].min()
        segments_df = pd.json_normalize(asset_s['segments'])
        segments_df['id'] = segments_df['id'].astype(str) + segments_df['kind']

        asset_dict = {
            'title': [asset_s['caption']],
            'valuable': [int(asset_s['isValuable'])],
            'TTR': [min_TTR],
            'Network': [list(segments_df.query("kind == ['network','channel']")['id'])],
            'Local': [list(segments_df.query("kind == 'local'")['id'])],
            'Physical': [list(segments_df.query("kind == 'physical'")['id'])],
        }
        asset_small_df = pd.DataFrame(data=asset_dict, index=[int(asset_id)])
        A_df = A_df.append(asset_small_df, ignore_index=False)
    return assets_filtered, A_df

def get_vulners_cmeasures(data_j, assets_filtered, intruder_id):
    vuln_df = pd.json_normalize(data_j['vulnerabilities'])
    vuln_df = vuln_df.set_index('id')
    #vuln_df = vuln_df.apply((lambda x, int_id: x if int_id in x['intruders']), axis = 1, int_id = intruder_id)
    vuln_df['probability.value'] = vuln_df.apply(
        lambda x: random.uniform(x['probability.start'], x['probability.end']) if x['probability.kind'] == 'range' else x['probability.value'], axis=1)
    vuln_df = vuln_df.apply(adjust_time, axis=1, prefix='timeToExploit')
    col_mapper = {
        'caption': 'Name',
        'av': 'AV',
        'pr': 'PR',
        'i': 'Imp',
        'scopeAv': 's.AV',
        'scopePr': 's.PR',
        'probability.value': 'Prob',
        'timeToExploit.interval': 't'
    }
    vulner = vuln_df[list(col_mapper.keys())]
    vulner = vulner.rename(columns=col_mapper)
    vulner['Imp'] = vulner['Imp'].astype(int)
    vulner['P_v'] = vulner['Prob']
    vulner['P_d'] = 0.
    vulner.loc[vulner.AV == 'P', 'AV'] = -np.inf
    vulner.loc[vulner.AV == 'L', 'AV'] = 0
    vulner.loc[vulner.AV == 'A', 'AV'] = 1
    # испарвление ошибки с определением вектора для случая "любая сеть"
    #vulner.loc[vulner.AV == 'N', 'AV'] = np.inf
    #legacy вариант (реализовано в продуктиве ПОАР)
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

    c_measures_df = pd.json_normalize(data_j['protectionMeasures'])
    c_measures_df = c_measures_df.set_index('id')
    c_measures_df = c_measures_df.fillna(value={'period.interval': 0})
    c_measures_df['preventionProbability.value'] = c_measures_df.apply(
        lambda x: random.uniform(x['preventionProbability.start'], x['preventionProbability.end']) if x['preventionProbability.kind'] == 'range' else x['preventionProbability.value'],
        axis=1)
    c_measures_df['detectionProbability.value'] = c_measures_df.apply(
        lambda x: random.uniform(x['detectionProbability.start'], x['detectionProbability.end']) if x['detectionProbability.kind'] == 'range' else x['detectionProbability.value'],
        axis=1)
    c_measures_df = c_measures_df.apply(adjust_time, axis=1, prefix='period')
    counter_m = c_measures_df[['caption', 'detectionProbability.value', 'period.interval']]
    c_col_mapper = {
        'caption': 'Описание',
        'period.interval': 'Период',
        'detectionProbability.value': 'P_d'
    }
    counter_m = counter_m.rename(columns=c_col_mapper)
    vulners_assets_dict = {}

    #TODO: найти, где потенциал в исходных данных Октоники
    k = 1

    for (idx, row) in assets_filtered.iterrows():
        vulners_assets_dict[row['id']] = vulner[vulner.index.isin(row['vulnerabilities'])].copy()
        #
        p_measure_df = pd.json_normalize(row['protectionMeasures'], record_path='vulnerabilities', max_level=0,
                                         meta=['protectionMeasureId'], errors='ignore')

        if not (p_measure_df.empty):
            # обработка превентивных мер
            prevention_df = p_measure_df.query('canPrevent')
            if not (prevention_df.empty):
                vuln_group = prevention_df.groupby('id')
                for vuln, v_idx in vuln_group.groups.items():
                    p_idx = list(prevention_df.loc[list(v_idx)]['protectionMeasureId'])
                    if p_idx:
                        base_prob = vulners_assets_dict[row['id']].at[vuln, 'Prob']
                        vulners_assets_dict[row['id']].at[vuln, 'P_v'] = (1 - c_measures_df.loc[p_idx][
                            'preventionProbability.value']).prod() * k * base_prob
            # обработка детектирующих мер
            detection_df = p_measure_df.query('canDetect')
            if not (detection_df.empty):
                vuln_group = detection_df.groupby('id')
                for vuln, v_idx in vuln_group.groups.items():
                    p_idx = list(detection_df.loc[list(v_idx)]['protectionMeasureId'])
                    #вторая часть условия отсекает периодические меры
                    if p_idx:
                        p_idx = list(counter_m.loc[p_idx][counter_m['Период'] == 0].index)
                    if p_idx:
                        vulners_assets_dict[row['id']].at[vuln, 'P_d'] = 1 - (
                                    1 - c_measures_df.loc[p_idx]['detectionProbability.value']).prod()
    return counter_m, vulners_assets_dict
def get_ctx0(data_j):
    ctx = pd.json_normalize(data_j['initialContext'])
    intruder_id = list(ctx['intruderId'].to_numpy())
    col_mapper = {
        'assetId': 'a_id',
        'pr': 'PR',
        'av': 'AV'
    }
    ctx = ctx.rename(columns=col_mapper)
    #ctx = ctx.drop(['intruderId'], axis=1)
    ctx['I'] = 0
    ctx.loc[ctx.AV == 'P', 'AV'] = -np.inf
    ctx.loc[ctx.AV == 'L', 'AV'] = 0
    ctx.loc[ctx.AV == 'A', 'AV'] = 1
    ctx.loc[ctx.AV == 'N', 'AV'] = 2

    ctx.loc[ctx.PR == 'N', 'PR'] = 0
    ctx.loc[ctx.PR == 'L', 'PR'] = 1
    ctx.loc[ctx.PR == 'H', 'PR'] = 2
    return ctx

#проверка работы кода
if __name__ == '__main__':
    #data_j = init_json('D:\Google\work\ПОАР\Model\simattack\Octonica\отладка_для_РАСУ.json')
    data_j = init_json('D:\YandexDisk\work\ПОАР\Model\simattack\Octonica\файл_для_отладки_симуляции_23_12_2021.json ')
    sub_name = ['Подсистема1', 'Подсистема2']
    intruder_id = 'fdaec6d3-e8f3-4206-b71d-01774404c129'

    sub_id = get_sub_id(data_j, sub_name)
    (assets_filtered, A_df) = get_assets_df(data_j,sub_id)
    (counter_m, vulners_assets_dict) = get_vulners_cmeasures(data_j, assets_filtered, intruder_id)
    Ctx_0 = get_ctx0(data_j)
    print(assets_filtered)

'''
  "initialContext": [
    {
        "assetId": 12 ,
        "intruderId": "fdaec6d3-e8f3-4206-b71d-01774404c129" ,
        "pr": "N" ,
        "av": "N"
    } ,
    {
      "assetId": 20 ,
      "intruderId": "603663d5-b312-46b3-9916-ab7d67474b00" ,
      "pr": "N" ,
      "av": "N"
    }
  ]
'''





