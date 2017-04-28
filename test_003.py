##################################################
##### Intrusion Detection using Multi-layer Perceptron
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
labels.value_counts()


##################################################
##### Multi-layer Perceptron
##################################################

from sklearn.neural_network import MLPClassifier
t0 = time()
clf = MLPClassifier()
clf = clf.fit(features,labels)
tt = time()-t0
print("Classified in {} seconds".format(round(tt,3)))


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
# label_names[0].value_counts().index.tolist()[0]

t0 = time()
pred = clf.predict(corrected)
tt = time() - t0
print("Assigned labels in {} seconds".format(round(tt,3)))

new_labels = pred

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

# Classified in 21.038 seconds


# Assigned labels in 0.469 seconds


# Accuracy 92.388 %
# Confusion Matrix: 

#  [[228612  21824]
#  [  1852  58741]]

# Classification Scores: 

#               precision    recall  f1-score   support

#     attack.       0.99      0.91      0.95    250436
#     normal.       0.73      0.97      0.83     60593

# avg / total       0.94      0.92      0.93    311029

# Hamming Loss 0.07612151921525002
# Jaccard Similarity Score 0.92387848078475
# Matthews corrcoef 0.7976215806483821
# Zero-One Loss 0.07612151921525001