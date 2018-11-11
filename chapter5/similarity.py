import argparse
import os
import subprocess

MIN_SIMILARITY = 0.8

pefile_strings = dict()

def jaccard_similarity(x,y):
    '''Code taken from https://dataconomy.com/3015/04/implementing-the-five-most-popular-similarity-measures-in-python/'''
    intersection_cardinality = len(set.intersection(*[set(x), set(y)]))
    union_cardinality = len(set.union(*[set(x), set(y)]))
    return intersection_cardinality/float(union_cardinality)

def get_similarities(path):
    print(':: Similarity Analyzer ::')
    # Analyzing PE-Files
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            if is_pefile(os.path.join(path, file)):
                print('[*] Analyzing PE-File', file)
                strings_for_pefile = get_strings(os.path.join(path, file)).split('\n')
                pefile_strings[file] = strings_for_pefile

    # Do similarity comparison
    keys = list(pefile_strings.keys())
    similarity_reached = []
    for i in range(len(keys)):
        for j in range(i+1, len(keys)):
            s1 = pefile_strings[keys[i]]
            s2 = pefile_strings[keys[j]]
            similarity = jaccard_similarity(s1, s2)
            #DEBUG: print('Similarity between', keys[i], 'and', keys[j],'=', similarity)
            if similarity > MIN_SIMILARITY:
                similarity_reached.append((keys[i], keys[j], similarity))

    # Print out items which are at least MIN_SIMILARITY to each other
    print()
    print('{:30s}'.format('Item 1'), '{:30s}'.format('Item 2'), '{:30s}'.format('Similarity'), sep='\t')
    for similarity_item in similarity_reached:
        print('{:30s}'.format(similarity_item[0][:30]), '{:30s}'.format(similarity_item[1][:30]), '{:30s}'.format(str(similarity_item[2])[:30]), sep='\t')

def get_strings(filepath):
    strings = subprocess.Popen(['strings', '-u', '-nobanner', '{}'.format(filepath)], stdout=subprocess.PIPE).communicate()[0]
    return strings.decode('utf-8')

def is_pefile(filepath):
    return open(filepath, 'rb').read(2) == b'MZ'

parser = argparse.ArgumentParser(description='Finds similarities between PE-Files based on their strings')
parser.add_argument('path', help='The path in which the pe files are stored')
args = parser.parse_args()
get_similarities(args.path)
