import struct
# import scipy.misc as sm
import imageio as sm
# from imageio import imsave
import numpy as np
import os
import shutil

def TransformToImage(pixelList,classname,step,imagepath):
    '''
    :param pixelList: 图像的像素列表
    :param classname: 分类的名称
    :param step: 第多少步
    :param imagepath: 保存图像的位置
    :return:
    '''

    traincount = (step//10)*9+(step%10)
    testcount = step//10
    if step % 10  in range(1,10):
        newPixels = np.reshape(pixelList,(32,32))
        if os.path.exists(imagepath+"\\train"):
            sm.imwrite(imagepath+"\\train\\"+classname+"_train"+str(traincount)+'.jpg',newPixels)
            #print("保存第"+str(traincount)+"个训练图像，位置是 ",imagepath + "\\train\\" + classname +"_train"+ str(traincount) + '.jpg')
        else:
            os.makedirs(imagepath+"\\train")
            #print("创建文件成功")
            sm.imwrite(imagepath + "\\train\\" + classname +"_train"+ str(traincount) + '.jpg', newPixels)
            #print("保存第" + str(traincount) + "个训练图像，位置是 ",imagepath + "\\train\\" + classname + "_train" + str(traincount) + '.jpg')
    if step % 10in [0]:
        newPixels = np.reshape(pixelList, (32, 32))
        if os.path.exists(imagepath+"\\test"):
            sm.imwrite(imagepath+"\\test\\"+classname+"_test"+str(traincount)+'.jpg',newPixels)
            #print("保存第"+str(traincount)+"个测试图像，位置是",imagepath + "\\test\\" + classname +"_test"+ str(testcount) + '.jpg')
        else:
            os.makedirs(imagepath + "\\test")
            #print("创建文件成功")
            sm.imwrite(imagepath + "\\test\\" + classname +"_test"+ str(traincount) + '.jpg', newPixels)
            #print("保存第" + str(traincount) + "个测试图像，位置是",imagepath + "\\test\\" + classname + "_test" + str(testcount) + '.jpg')
def FillImage(step,classname,count,imagepath):
    '''
    :param step: 当前进行到多少步
    :param classname: 分类的名称
    :param count: 将要到达的步数
    :param imagepath: 保存文件的位置
    :return:复制的个数
    '''
    temp = 0
    new_train_num = (step//10)*9+(step%10)
    mult = (((count//10)*9)//new_train_num)-1
    #print(mult)
    quot = ((count//10)*9) % new_train_num
    for i in range(1,mult+1):
        for j in range(1,new_train_num+1):
            current_step = new_train_num*i+j
            shutil.copyfile(imagepath+"\\train\\"+classname+"_train"+str(j)+".jpg",imagepath+"\\train\\"+classname+"_train"+str(current_step)+".jpg")
            temp +=1
    for z in range(1,quot+1):
        current_step = (mult+1)*new_train_num+z
        shutil.copyfile(imagepath + "\\train\\" + classname + "_train" + str(z) + ".jpg",imagepath + "\\train\\" + classname + "_train" + str(current_step) + ".jpg")
        temp += 1
    return temp
def ReadFile(path,classification,count,imagepath):
    '''
    :param path: 存放pcap文件的地址
    :param classification: 列表 表示分类的种类
    :param count: 最多制作的包的个数
    :param imagepath: 保存图像的位置
    :return: 返回是以分类名为Key，value是所有该分类的不超过count个的列表
    '''
    num = 0
    #加入VPN流量分类


    print(classification)

    for classname in classification:
        step = 0
        temp = 0
        total = 0
        for onepcap in os.listdir(path):
            if onepcap.startswith(classname) and onepcap.endswith(".pcap"):
                with open(path + "\\" + onepcap, 'rb') as f:
                    data = f.read()
                    pcap_header = {}
                    pcap_header['magic_number'] = data[0:4]
                    pcap_header['version_major'] = data[4:6]
                    pcap_header['version_minor'] = data[6:8]
                    pcap_header['thiszone'] = data[8:12]
                    pcap_header['sigfigs'] = data[12:16]
                    pcap_header['snaplen'] = data[16:20]
                    pcap_header['linktype'] = data[20:24]
                    # print(pcap_header)
                    pcap_packet_header = {}
                    i = 24
                    while (i < len(data)):
                        pcap_packet_header['GMTtime'] = data[i:i + 4]
                        pcap_packet_header['MicroTime'] = data[i + 4:i + 8]
                        pcap_packet_header['caplen'] = data[i + 8:i + 12]
                        pcap_packet_header['len'] = data[i + 12:i + 16]
                        #求出此包的长度
                        packet_len = struct.unpack('I', pcap_packet_header['len'])[0]
                        #print(pcap_packet_header['len'], packet_len)
                        if packet_len<=1024:
                            pixels = np.zeros(1024)
                            packet_pixel = [pixel for pixel in data[i+16:i+16+packet_len]]
                            pixels[0:len(packet_pixel)] = packet_pixel
                        else:
                            pixels = np.zeros(1024)
                            packet_pixel = [pixel for pixel in data[i + 16:i + 16 + 1024]]
                            pixels[0:len(packet_pixel)] = packet_pixel
                        step += 1
                        num += 1
                        pixels = pixels.astype(np.uint8)
                        TransformToImage(pixels,classname,step,imagepath)
                        i = i + packet_len + 16
                        if step >= count:
                            break
                print(onepcap,step)
            if  step>=count:
                total = int(count*0.9)
                break
        if step < count:
            temp = FillImage(step, classname, count, imagepath)
            total = (step//10)*9+step%10 + temp
            num += temp
        print('保存'+classname+"类别共"+str(total)+"个,其中扩充"+str(temp)+"个")
    print("共保存"+str(num)+"个训练测试图像包")


if __name__ == '__main__':
    path = "E:\\DL\\DataSet\\CompletePCAPs"
    imagepath = "E:\\DLResult\\simple\\5000\\TransformImage"
    classification = ['aim','facebook','email','netflix','hangouts','icq','youtube','skype','vimeo','spotify']
    #classification = ['aim']
    ReadFile(path,classification,5000,imagepath)


