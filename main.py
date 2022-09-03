from __future__ import print_function
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torchvision import datasets, transforms
import numpy as np
import matplotlib.pyplot as plt
import torch.utils.data as Data
import copy
import os
import random
import struct
import re
import cv2 as cv
import matplotlib.pyplot as plt
import numpy as np
import imageio as sm


class Net(nn.Module):
    def __init__(self,batch_size):
        super(Net, self).__init__()
        self.batch_size = batch_size
        self.conv1 = nn.Conv2d(1, 32, kernel_size=3)
        self.conv2 = nn.Conv2d(32, 64, kernel_size=3)
        self.conv3 = nn.Conv2d(64, 64, kernel_size=3)
        self.conv2_drop = nn.Dropout2d()
        self.dense1 = torch.nn.Linear(64*1024, 1024)
        self.dense2 = torch.nn.Linear(1024, 64)
        self.dense3 = torch.nn.Linear(64, 10)

    def forward(self, x):
        x = F.relu(F.max_pool2d(self.conv1(x), kernel_size=2))
        x = F.relu(F.max_pool2d(self.conv2(x), kernel_size=2))
        x = F.relu(self.conv3(x))
        x = torch.reshape(x, (-1,1024))
        #print(x.size())
        #x = self.dense1(x)
        #         print(x.size())
        x = self.dense2(x)
        x = self.dense3(x)
        return x

def Transform_one_ToImage(path):
    i=24
    pcap_packet_header = {}
    with open(path , 'rb') as f:
        data=f.read()
        pcap_packet_header['len'] = data[i + 12:i + 16]
        packet_len = struct.unpack('I', pcap_packet_header['len'])[0]
        print("packet_length:",packet_len)
        if packet_len<=1024:
            pixels = np.zeros(1024)
            packet_pixel = [pixel for pixel in data[i+16:i+16+packet_len]]
            pixels[0:len(packet_pixel)] = packet_pixel
            print(pixels)
        else:
            pixels = np.zeros(1024)
            packet_pixel = [pixel for pixel in data[i + 16:i + 16 + 1024]]
            pixels[0:len(packet_pixel)] = packet_pixel
        pixels = pixels.astype(np.uint8)
        image=np.reshape(pixels,(32,32))
        plt.imshow(image)
        plt.show()
        print(image)
# path = "D:\\pycharm\\pythonProject\\DataSet\\USTC-TFC2016\\BitTorrent.pcap"
# Transform_one_ToImage(path)

def SaveImage(pixelList, classname, step, imagepath):
    traincount = (step // 10) * 9 + (step % 10)
    testcount = step // 10
    if step % 10 in range(1, 10):
        newPixels = np.reshape(pixelList, (32, 32))
        if os.path.exists(imagepath + "\\train"):
            sm.imwrite(imagepath + "\\train\\" + classname + "_train" + str(traincount) + '.jpg', newPixels)
        else:
            os.makedirs(imagepath + "\\train")
            sm.imwrite(imagepath + "\\train\\" + classname + "_train" + str(traincount) + '.jpg', newPixels)
    if step % 10 in [0]:
        newPixels = np.reshape(pixelList, (32, 32))
        if os.path.exists(imagepath + "\\test"):
            sm.imwrite(imagepath + "\\test\\" + classname + "_test" + str(testcount) + '.jpg', newPixels)
        else:
            os.makedirs(imagepath + "\\test")
            sm.imwrite(imagepath + "\\test\\" + classname + "_test" + str(testcount) + '.jpg', newPixels)


def TransformToImage(path, count):
    classification = ['BitTorrent', 'Facetime', 'FTP', 'Virut', 'MySQL', 'Weibo', 'Skype', 'SMB', 'Gmail',
                      'Outlook']
    for classname in classification:

        for onepcap in os.listdir(path):
            if onepcap.startswith(classname) and onepcap.endswith(".pcap"):
                step = 0
                i = 24
                with open(path + "//" + onepcap, 'rb') as f:
                    data = f.read()
                    pcap_packet_header = {}
                    while (i < len(data)):

                        pcap_packet_header['len'] = data[i + 12:i + 16]
                        packet_len = struct.unpack('I', pcap_packet_header['len'])[0]
                        print("packet_length:", packet_len)
                        if packet_len <= 1024:
                            pixels = np.zeros(1024)
                            packet_pixel = [pixel for pixel in data[i + 16:i + 16 + packet_len]]
                            pixels[0:len(packet_pixel)] = packet_pixel
                            #print(pixels)
                        else:
                            pixels = np.zeros(1024)
                            packet_pixel = [pixel for pixel in data[i + 16:i + 16 + 1024]]
                            pixels[0:len(packet_pixel)] = packet_pixel
                        pixels = pixels.astype(np.uint8)
                        image = np.reshape(pixels, (32, 32))
                        step = step + 1
                        imagepath = "D:\\pycharm\\pythonProject\\DLResult\\USTC-TFC2016To10\\TransformImage"
                        SaveImage(image, classname, step, imagepath)
                        #             plt.imshow(image)
                        #             plt.show()
                        i = i + packet_len + 16
                        if step >= count:
                            break

#采用one-hot编码
labeldict = {}
def deal_image(path, classname=None):
    count = 0
    templabels = [0 for i in range(10)]
    images = []
    labels = []
    imagenamelist = []
    if classname == None:
        imagenamelist = [path + "\\" + name for name in os.listdir(path) if name.lower().endswith('jpg')]#找到所有图片路径
    else:
        imagenamelist = [path + "\\" + name for name in os.listdir(path) if
                         name.lower().endswith('jpg') and name.lower().startswith(classname)]
    random.shuffle(imagenamelist)
    random.shuffle(imagenamelist)
    for i in imagenamelist:
        image = cv.imread(i, flags=0)
        image = image[np.newaxis,:, :]
        images.append(image)
        pattern = re.compile('^[a-z]+')
        vpnpattern = re.compile('(vpn_[a-z]+)')
        name = i.split('\\')[-1]
        if name.startswith('vpn'):
            name = vpnpattern.findall(name.lower())[0]
        else:
            name = pattern.findall(name.lower())[0]    #get label
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
    images = np.array(images)
    images = images / 255.0
    labels = np.array(labels)
#     print(labeldict)
    return images, labels


def fgsm_attack(sample, data_grad,epsilon=0.5):
    # Collect the element-wise sign of the data gradient
    sign_data_grad = data_grad.sign()
    # Create the perturbed image by adjusting each pixel of the input image
    perturbed_image = sample + epsilon*sign_data_grad
    # Adding clipping to maintain [0,1] range
    perturbed_image = torch.clamp(perturbed_image, 0, 1)
    # Return the perturbed image
    return perturbed_image

def fgsm_test(model,device,fgsm_path="D:\\pycharm\\pythonProject\\fgsm_sample"):
    x, y = deal_image(fgsm_path)
    x = x.astype(np.float32)
    print(y)
    y = np.argmax(y, axis=1)
    cross_loss = nn.CrossEntropyLoss()
    count = 0
    sum = len(x)
    for sample,target in zip(x,y):
        # print("sample")
        # print(sample)
        # print(sample.shape)
        # print("target")
        target = target[np.newaxis]
        # print(target.shape)
        # print(target)
        sample = torch.from_numpy(sample)
        sample = sample.to(device)
        sample.requires_grad = True
        output = model(sample)
        #print(output.size())
        # output = output.cpu().detach().numpy()
        # init_output = np.argmax(output,axis=1)
        init_output = output.max(1, keepdim=True)[1]
        target = torch.tensor(target)
        target = target.to(device)
        loss = cross_loss(output, target)
        print("loss:",loss)
        model.zero_grad()
        loss.backward()
        data_grad = sample.grad.data
        perturbed_data = fgsm_attack(sample,data_grad, 0.1 )
        output = model(perturbed_data)
        final_pred = output.max(1, keepdim=True)[1]
        if init_output != final_pred :
            count = count+1

        print("original result:",target)
        print("init result:",init_output)
        print("final prediction:",final_pred)
    print("error:",count/sum)

def test_loss(test_datapath,model,device):
    x_test, y_test = deal_image(test_datapath)
    y_test = np.argmax(y_test, axis=1)
    x_test = x_test.astype(np.float32)
    x_test = torch.from_numpy(x_test)
    y_test = torch.from_numpy(y_test)
    x_test, y_test = x_test.to(device), y_test.to(device)
    pre_data = model(x_test)
    print("pre_data.size:",pre_data.size())
    cross_loss = nn.CrossEntropyLoss()
    loss = cross_loss(pre_data, y_test)
    print("loss:",loss)
    pre_data = pre_data.cpu().detach().numpy()
    y_test =y_test.cpu().detach().numpy()
    pre_data = np.argmax(pre_data,axis=1)
    count =0
    for pre,tar in zip(pre_data,y_test):
        if pre != tar:
            count = count+1
    result = 1-count/(len(pre_data))
    print("准确率:",result)

    pre_data = pre_data[0:100]
    y_test = y_test[0:100]
    print(y_test)
    print(pre_data)
    plt.cla()
    plt.plot(y_test, color='lightseagreen')

    plt.plot(pre_data,color='darkorange')
    plt.text(0.5, 0, 'Loss=%.4f' % loss.data.cpu().detach().numpy(), fontdict={'size': 20, 'color': 'red'})
    plt.show()

if __name__ == '__main__':
    # path = "D:\\pycharm\\pythonProject\\DataSet\\USTC-TFC2016"
    # TransformToImage(path,5000)         #转pcap包为image

    Batch_size = 64
    datapath = "D:\\pycharm\\pythonProject\\DLResult\\USTC-TFC2016To10\\TransformImage\\train"
    test_datapath = "D:\\pycharm\\pythonProject\\DLResult\\USTC-TFC2016To10\\TransformImage\\test"
    use_cuda = True
    print("CUDA Available: ", torch.cuda.is_available())
    device = torch.device("cuda" if (use_cuda and torch.cuda.is_available()) else "cpu")
    x, y = deal_image(datapath)
    y = np.argmax(y, axis=1)
    # print("y shape:")
    # print(y.shape)

    x = x.astype(np.float32)
    x = torch.from_numpy(x)
    y = torch.from_numpy(y)
    x, y = x.to(device), y.to(device)
    torch_dataset = Data.TensorDataset(x, y)
    loader = Data.DataLoader(
        dataset=torch_dataset,
        batch_size=Batch_size,
        shuffle=True,
        num_workers=0,
    )
    model = Net(Batch_size).to(device)
    optimizer = torch.optim.SGD(model.parameters(), lr=0.2)
    # loss_func=torch.nn.MSELoss()
    # summary(model,(1,32,32),batch_size=5,device="cpu")
    pre_list=[]
    cross_loss = nn.CrossEntropyLoss()
    for epoch in range(5):
        print("epoch:", epoch)
        loss_sum = 0
        for step, (batch_x, batch_y) in enumerate(loader):
            #print("batch_x.size():",batch_x.size())

            prediction = model(batch_x)  # input x and predict based on x
            #         loss = loss_func(prediction, batch_y)     # must be (1. nn output, 2. target)
            # batch_y = batch_y.view(batch_y.shape[0]*batch_y.shape[1])
            # prediction = prediction.view(prediction.shape[0] * prediction.shape[1])
            #print("batch_y.size():",batch_y.size())
            batch_y = batch_y.to(torch.int64)  # TODO: ReID. [matched_anchor], float16 to int
            #print(prediction.size())
            loss = cross_loss(prediction, batch_y)
            # print("loss:",loss)
            loss_sum = loss_sum+loss
            # 5.3反向传播
            optimizer.zero_grad()  # clear gradients for next train
            loss.backward()  # backpropagation, compute gradients
            optimizer.step()  # apply gradients
        print("loss_sum:",loss_sum)

    #torch.save(model, 'model.pkl')
    fgsm_test(model,device)    #如果没有model先去掉前一行注释生成model
    #test_loss(test_datapath,model,device)


    #         prediction = prediction.cpu().detach().numpy()
    #         prediction = prediction.flatten()
    #         # print(prediction.shape)
    #         pre_list.append(prediction)
    # x = x.cpu().detach().numpy()
    # y = y.cpu().detach().numpy()
    # print("x size:",x.shape)
    # print("y size:",y.shape)
    # pre_list = np.array(pre_list)
    # pre_list = pre_list.flatten()
    # pre = []
    # pre = np.array(pre)
    # for temp_1 in pre_list:
    #     pre = np.concatenate((temp_1,pre),axis=0)
    # pre = pre.reshape(-1,10)
    # pre = np.argmax(pre, axis=1)
    # print(pre)
    # #pre_list = pre_list.reshape(-1,10)
    # y = y[0:100]
    # pre = pre[0:100]
    # #prediction = prediction.cpu().detach().numpy()
    # # print("prediction size:",prediction.shape)
    # plt.cla()
    # plt.plot(y, color='lightseagreen')
    # plt.plot(pre,color='darkorange')
    # plt.text(0.5, 0, 'Loss=%.4f' % loss.data.cpu().detach().numpy(), fontdict={'size': 20, 'color': 'red'})
    # plt.show()


