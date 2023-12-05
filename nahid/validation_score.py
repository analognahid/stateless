
from sklearn.metrics import confusion_matrix, f1_score
import math 
import seaborn as sns
import pickle
import torch
from sklearn.metrics import precision_recall_fscore_support , accuracy_score






import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix
from sklearn.metrics import multilabel_confusion_matrix,ConfusionMatrixDisplay
import seaborn as sns

def plot_confusion_matrix(true_labels, predicted_labels, TYPE_MAPPING, label='Stateformer_confusion_matrix_O2'):

    class_labels = list(TYPE_MAPPING.keys())  
    class_labels = [c for c in class_labels]

    cm = confusion_matrix(true_labels, predicted_labels ) 
    
    conf_per_class = cm.diagonal()/cm.sum(axis=1)
    average_acc = sum([i for i in conf_per_class  if not math.isnan(i)] )/len(conf_per_class)
    
    print('CONFUSION PER CLASS',conf_per_class,average_acc)
    
    fig, ax = plt.subplots(figsize=(20, 20))
    
    res = sns.heatmap(cm,
            annot=True , cmap="Blues" , fmt='g' , xticklabels=class_labels,linewidths = .01,
                      yticklabels=class_labels,linecolor="Gray")
    for _, spine in res.spines.items():
        spine.set_visible(True)
        spine.set_linewidth(1)
    
    plt.ylabel('Actual',fontsize=13)
    plt.xlabel('Prediction',fontsize=13)
    plt.title('Confusion Matrix',fontsize=17)
    plt.savefig(label+'_conf.pdf',dpi=200)
    plt.show()
    plt.close()
    print('here!!!')






pkl_path = '/home/raisul/stateformer/result/validation_02.pkl'

with open(pkl_path, 'rb') as handle:
    validation_targets_nz ,validation_preds_nz = pickle.load(handle)

# conf_matrix = confusion_matrix(validation_targets_nz, validation_preds_nz)
# conf_per_class = conf_matrix.diagonal()/conf_matrix.sum(axis=1)
# #TODO nahid fix -1
# average_acc = sum([i for i in conf_per_class  if not math.isnan(i)] )/len(conf_per_class-1)
# print('DBG  conf_matrix' ,conf_matrix)
# print("DBG conf %" , conf_per_class , '  avg ' ,average_acc)
    



with open('data-bin/finetune/x86-O0/label/dict.txt') as f:
    lines = f.readlines()

map = {}
for y, line in enumerate(lines):
    if y==0 or y>=37:
        continue
    label = line.split(' ')[0]
    # handle no-access
    map[label] = y-1

print(torch.bincount(validation_targets_nz))


with open('data-src/finetune/x86-O0/valid.label') as f:
    lines = f.readlines()

#sanity check
# from collections import Counter
# def word_count(fname):
#         with open(fname) as f:
#                 return Counter(f.read().split())

# print("Number of words in the file :",word_count("data-src/finetune/x86-O0/valid.label"))

print(validation_targets_nz.shape , validation_preds_nz.shape)
validation_targets_nz = validation_targets_nz.numpy()
validation_preds_nz = validation_preds_nz.numpy()
down_targets = []
down_preds = []
count_map = {}
MAX_COUNT = 40000
for i,vt in enumerate(validation_targets_nz):
    if vt not in count_map:
        count_map[vt] = 0
    else:
        count_map[vt] = count_map[vt] +1
    
    # if count_map[vt]>MAX_COUNT:
    #     continue
    
    # print(vt,validation_preds_nz [i])

    down_targets.append(vt-1)
    down_preds.append(validation_preds_nz [i]-1)



print('tetst  : ' ,len(down_targets))
print(len(down_targets) ,  len(down_preds))
conf_matrix = confusion_matrix(down_targets, down_preds)
conf_per_class = conf_matrix.diagonal()/conf_matrix.sum(axis=1)
#TODO nahid fix -1
average_acc = sum([i for i in conf_per_class  if not math.isnan(i)] )/len(conf_per_class-1)
print('DBG  conf_matrix' ,conf_matrix)
print("DBG conf %" , conf_per_class , '  avg ' ,average_acc)


accuracy = accuracy_score(down_targets, down_preds)    
precision, recall, f1, _ = precision_recall_fscore_support(down_targets,down_preds,average='weighted')
print('accuracy, precision, recall, f1: ',accuracy, precision, recall, f1)

plot_confusion_matrix(down_targets, down_preds, map, label = "stateformer_O2")#true_labels, predicted_labels, TYPE_MAPPING


# y_true = [0, 1, 2, 0, 1, 2]
# y_pred = [0, 2, 1, 0, 0, 1]
# labels = ['0', '1', '2']

f1_scores = f1_score(down_targets, down_preds, average=None)#, labels=  list(map.keys()))
print('f1_scores ',f1_scores)
f1_scores_with_labels = {label:score for label,score in zip(list(map.keys()), f1_scores)}
print(f1_scores_with_labels)
###########

with open('data-bin/finetune/x86-O0/label/dict.txt') as f:
    lines = f.readlines()
untouched_labels = []
for y, line in enumerate(lines):

    label = line.split(' ')[0]
    untouched_labels.append(label)
untouched_score = f1_score(validation_targets_nz, validation_preds_nz, average=None)

print('untouched_score: ',untouched_score)

print(untouched_labels, len(untouched_labels),'untouched_labels')
print('untouched_score', untouched_score, len(untouched_score),'untouched_score')
untouched_f1_scores_with_labels = {label:score for label,score in zip(untouched_labels, untouched_score)}

print("untouched_f1_scores_with_labels", untouched_f1_scores_with_labels)