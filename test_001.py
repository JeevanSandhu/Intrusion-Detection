##################################################
##### Intrusion Detection using K Means (k=59)
##################################################

import pandas
from time import time

##################################################
##### Loading the data
##################################################

col_names = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"]

kdd_data_10percent = pandas.read_csv("dataset/kddcup.data_10_percent_corrected", header=None, names = col_names)

# kdd_data_10percent.describe()
# kdd_data_10percent['label'].value_counts()

##################################################
##### Features Selection
##################################################

num_features = [
    "duration","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

features = kdd_data_10percent[num_features].astype(float)

# features.describe()

##################################################
##### Reduce the outputs to only attack/normal
##################################################

labels = kdd_data_10percent['label'].copy()
labels[labels!='normal.'] = 'attack.'
# labels.value_counts()


##################################################
##### KMeans clustering
##################################################

from sklearn.cluster import KMeans
k = 59
km = KMeans(n_clusters = k)

t0 = time()
km.fit(features)
tt = time()-t0
print("Clustered in {} seconds".format(round(tt,3)))

##################################################
##### Get labels for each cluster formed
##################################################

# labels = kdd_data_10percent['label']
label_names = list(map(
    lambda x: pandas.Series([labels[i] for i in range(len(km.labels_)) if km.labels_[i]==x]), 
    range(k)))


for i in range(k):
    print("Cluster {} labels:".format(i))
    print(label_names[i].value_counts())
    print()


##################################################
##### Get one label for each cluster based on max frequency
##################################################

clusters = []
for i in range(len(label_names)):
    clusters.append(label_names[i].value_counts().index.tolist()[0])


##################################################
##### Load the test data
##################################################

kdd_data_corrected = pandas.read_csv("dataset/correctedDataset", header=None, names = col_names)
kdd_data_corrected['label'].value_counts()

corrected = kdd_data_corrected[num_features].astype(float)
true_labels = kdd_data_corrected['label'].copy()
true_labels[true_labels!='normal.'] = 'attack.'

##################################################
##### Predictions
##################################################

t0 = time()
pred = km.predict(corrected)
tt = time() - t0
print("Assigned clusters in {} seconds".format(round(tt,3)))

new_labels = [] 
for i in pred:                   
    new_labels.append(clusters[i])


##################################################
##### Calculate Metrics
##################################################

from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, hamming_loss, jaccard_similarity_score, matthews_corrcoef, zero_one_loss

accuracy_score = accuracy_score(true_labels, new_labels)
print("\n\nAccuracy {} %".format(round(accuracy_score*100,3)))

confusion_matrix = confusion_matrix(true_labels, new_labels)
print("\n\nConfusion Matrix: \n\n {}".format(confusion_matrix))

classification_report = classification_report(true_labels, new_labels)
print("\n\nClassification Scores: \n\n {}".format(classification_report))

hamming_loss = hamming_loss(true_labels, new_labels)
print("\n\nHamming Loss {}".format(hamming_loss))

jaccard_similarity_score = jaccard_similarity_score(true_labels, new_labels)
print("\n\nJaccard Similarity Score {}".format(jaccard_similarity_score))

matthews_corrcoef = matthews_corrcoef(true_labels, new_labels)
print("\n\nMatthews corrcoef {}".format(matthews_corrcoef))

zero_one_loss = zero_one_loss(true_labels, new_labels)
print("\n\nZero-One Loss {}".format(zero_one_loss))


##################################################
##### OUTPUT
##################################################

# Clustered in 93.176 seconds


# Cluster 0 labels:
# attack.    228278
# normal.      5770
# dtype: int64

# Cluster 1 labels:
# attack.    1
# dtype: int64

# Cluster 2 labels:
# attack.    59
# dtype: int64

# Cluster 3 labels:
# attack.    15
# normal.     1
# dtype: int64

# Cluster 4 labels:
# normal.    22
# dtype: int64

# Cluster 5 labels:
# normal.    4
# dtype: int64

# Cluster 6 labels:
# normal.    24
# dtype: int64

# Cluster 7 labels:
# attack.    2173
# normal.      35
# dtype: int64

# Cluster 8 labels:
# normal.    1
# dtype: int64

# Cluster 9 labels:
# normal.    3
# dtype: int64

# Cluster 10 labels:
# normal.    2
# dtype: int64

# Cluster 11 labels:
# normal.    288
# attack.      1
# dtype: int64

# Cluster 12 labels:
# normal.    7
# dtype: int64

# Cluster 13 labels:
# normal.    3341
# attack.       8
# dtype: int64

# Cluster 14 labels:
# normal.    17
# dtype: int64

# Cluster 15 labels:
# normal.    33
# dtype: int64

# Cluster 16 labels:
# normal.    2
# attack.    1
# dtype: int64

# Cluster 17 labels:
# normal.    6
# attack.    1
# dtype: int64

# Cluster 18 labels:
# normal.    1
# dtype: int64

# Cluster 19 labels:
# normal.    958
# dtype: int64

# Cluster 20 labels:
# attack.    112363
# normal.     17855
# dtype: int64

# Cluster 21 labels:
# normal.    9319
# attack.     294
# dtype: int64

# Cluster 22 labels:
# normal.    673
# attack.     11
# dtype: int64

# Cluster 23 labels:
# normal.    407
# attack.     30
# dtype: int64

# Cluster 24 labels:
# normal.    16
# dtype: int64

# Cluster 25 labels:
# attack.    1
# dtype: int64

# Cluster 26 labels:
# normal.    5
# attack.    1
# dtype: int64

# Cluster 27 labels:
# normal.    1
# dtype: int64

# Cluster 28 labels:
# normal.    1
# dtype: int64

# Cluster 29 labels:
# normal.    1969
# attack.       1
# dtype: int64

# Cluster 30 labels:
# normal.    4
# dtype: int64

# Cluster 31 labels:
# normal.    721
# attack.      2
# dtype: int64

# Cluster 32 labels:
# normal.    1
# dtype: int64

# Cluster 33 labels:
# normal.    57
# attack.     1
# dtype: int64

# Cluster 34 labels:
# normal.    3
# attack.    1
# dtype: int64

# Cluster 35 labels:
# normal.    4
# dtype: int64

# Cluster 36 labels:
# normal.    4731
# attack.      14
# dtype: int64

# Cluster 37 labels:
# normal.    2
# dtype: int64

# Cluster 38 labels:
# normal.    18
# dtype: int64

# Cluster 39 labels:
# normal.    35
# dtype: int64

# Cluster 40 labels:
# normal.    2818
# dtype: int64

# Cluster 41 labels:
# normal.    1069
# attack.      32
# dtype: int64

# Cluster 42 labels:
# normal.    28282
# attack.      591
# dtype: int64

# Cluster 43 labels:
# normal.    86
# attack.    19
# dtype: int64

# Cluster 44 labels:
# attack.    56
# normal.    41
# dtype: int64

# Cluster 45 labels:
# normal.    173
# dtype: int64

# Cluster 46 labels:
# normal.    1
# dtype: int64

# Cluster 47 labels:
# normal.    25
# dtype: int64

# Cluster 48 labels:
# normal.    4
# dtype: int64

# Cluster 49 labels:
# normal.    9
# dtype: int64

# Cluster 50 labels:
# normal.    4
# dtype: int64

# Cluster 51 labels:
# normal.    813
# attack.     23
# dtype: int64

# Cluster 52 labels:
# normal.    3
# dtype: int64

# Cluster 53 labels:
# attack.    52756
# normal.       33
# dtype: int64

# Cluster 54 labels:
# normal.    14571
# attack.        8
# dtype: int64

# Cluster 55 labels:
# normal.    2
# dtype: int64

# Cluster 56 labels:
# normal.    2543
# attack.       2
# dtype: int64

# Cluster 57 labels:
# normal.    1
# dtype: int64

# Cluster 58 labels:
# normal.    463
# dtype: int64


# Assigned clusters in 0.416 seconds


# Accuracy 93.077 %

# Confusion Matrix: 
#  [[240756   9680]
#  [ 11854  48739]]


# Classification Scores: 

#               precision    recall  f1-score   support

#     attack.       0.95      0.96      0.96    250436
#     normal.       0.83      0.80      0.82     60593

# avg / total       0.93      0.93      0.93    311029


# Hamming Loss 0.06923470158731179
# Jaccard Similarity Score 0.9307652984126882
# Matthews corrcoef 0.7764687975671298
# Zero-One Loss 0.06923470158731182