import copy
import os
import random
import re
from sklearn.metrics import classification_report
import cv2 as cv
# from tensorflow.keras import layers, models
import matplotlib.pyplot as plt
import numpy as np
import tensorflow as tf
from tensorflow import keras



datapath = "E:\\DLResult\\simple\\3476\\TransformImage\\train"
testpath = "E:\\DLResult\\simple\\3476\\TransformImage\\test"
modelpath = "E:\\DLResult\\simple\\3476\\20200520Result"
pltpath = "E:\\DLResult\\simple\\3476\\20200520Result"
labeldict = {}
classkinds = 10
def deal_image(path, classname=None):

    count = 0
    templabels = [0 for i in range(10)]
    images = []
    labels = []
    imagenamelist = []
    if classname == None:
        imagenamelist = [path + "\\" + name for name in os.listdir(path) if name.lower().endswith('jpg')]
    else:
        imagenamelist = [path + "\\" + name for name in os.listdir(path) if
                         name.lower().endswith('jpg') and name.lower().startswith(classname)]
    random.shuffle(imagenamelist)
    random.shuffle(imagenamelist)

    for i in imagenamelist:
        image = cv.imread(i, flags=0)
        # image = cv.cvtColor(image,cv.COLOR_BGR2GRAY)
        # print(image.shape)
        image = image[:, :, np.newaxis]
        # print(image.shape,image)
        images.append(image)
        pattern = re.compile('^[a-z]+')
        vpnpattern = re.compile('(vpn_[a-z]+)')
        name = i.split('\\')[-1]
        if name.startswith('vpn'):
            name = vpnpattern.findall(name.lower())[0]
        else:
            name = pattern.findall(name.lower())[0]
        # print('label name',name)
        if name in labeldict:
            label = labeldict[name]
            labels.append(label)
            count += 1
        else:
            labellength = len(labeldict)
            templabel = copy.deepcopy(templabels)
            templabel[labellength] = 1
            labeldict.update({name: templabel})
            label = templabel
            labels.append(label)
            count += 1
        # if count %10000 == 0:
        #     print("处理完{}个图片".format(count))
    images = np.array(images)
    images = images / 255.0
    labels = np.array(labels)
    # print(images.shape,labeldict)
    print(labeldict)
    return images, labels



def create_model():
    model = tf.keras.models.Sequential([
    keras.layers.Conv2D(32, (3, 3), activation='relu', input_shape=(32, 32, 1)),
    keras.layers.MaxPooling2D((2, 2)),
    keras.layers.Conv2D(64, (3, 3), activation='relu'),
    keras.layers.MaxPooling2D((2, 2)),
    keras.layers.Conv2D(64, (3, 3), activation='relu'),
    keras.layers.Flatten(),
    keras.layers.Dense(64, activation='relu'),
    keras.layers.Dense(10)
    ])
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
                  loss=tf.keras.losses.CategoricalCrossentropy(from_logits=True),
                  metrics=['accuracy'])
    return model



train_images, train_labels = deal_image(datapath)
test_images, test_labels = deal_image(testpath)



# print(train_images,train_labels)
# print(test_images,test_labels)
model = create_model()
model.summary()
history = model.fit(train_images, train_labels, verbose=2, epochs=50,
                    validation_split=0.1)
model.save(modelpath+"\\"+"my_model.h5")


plt.plot(history.history['accuracy'], label='train_accuracy')
plt.plot(history.history['val_accuracy'], label='val_accuracy')
plt.xlabel('Epoch')
plt.ylabel('Accuracy')
plt.ylim([0, 1])
plt.legend(loc='lower right')
plt.savefig(pltpath+"\\"+"result.jpg")
plt.show()



test_loss, test_acc = model.evaluate(test_images, test_labels, verbose=2)
print(test_loss, test_acc)


Y_test = np.argmax(test_labels, axis=1)
y_pred = model.predict_classes(test_images)
print(classification_report(Y_test, y_pred))

