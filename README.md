# Intrusion-Detection

Intrusion Detection using various Data Mining Techniques (KDD Cup 1999 Data)

Dataset available on http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html

### Techniques Used:

1. K Means (K=59)

    Accuracy 93.077 %

|             | precision | recall | f1-score | support |
| ----------- | --------- | ------ | -------- | ------- |
| attack.     | 0.95      | 0.96   | 0.96     | 250436  |
| normal.     | 0.83      | 0.80   | 0.82     | 60593   |
| avg / total | 0.93      | 0.93   | 0.93     | 311029  |


2. Decision Trees

     Accuracy 92.956 %


|             | precision | recall | f1-score | support |
| ----------- | --------- | ------ | -------- | ------- |
| attack.     | 1.0       | 0.91   | 0.95     | 250436  |
| normal.     | 0.74      | 0.99   | 0.85     | 60593   |
| avg / total | 0.95      | 0.93   | 0.93     | 311029  |



3. Multi-Level Perceptron

     Accuracy 92.388 %
     
|             | precision | recall | f1-score | support |
| ----------- | --------- | ------ | -------- | ------- |
| attack.     | 0.99      | 0.91   | 0.95     | 250436  |
| normal.     | 0.73      | 0.97   | 0.83     | 60593   |
| avg / total | 0.94      | 0.92   | 0.93     | 311029  |

4. Random Forrest Classifier

     Accuracy 92.775 %
     
|             | precision | recall | f1-score | support |
| ----------- | --------- | ------ | -------- | ------- |
| attack.     | 1.0       | 0.91   | 0.95     | 250436  |
| normal.     | 0.73      | 0.99   | 0.84     | 60593   |
| avg / total | 0.95      | 0.93   | 0.93     | 311029  |

5. K Neighbours

     Accuracy 92.469 %

|             | precision | recall | f1-score | support |
| ----------- | --------- | ------ | -------- | ------- |
| attack.     | 1.0       | 0.91   | 0.95     | 250436  |
| normal.     | 0.72      | 0.99   | 0.84     | 60593   |
| avg / total | 0.94      | 0.92   | 0.93     | 311029  |

