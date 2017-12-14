from decimal import Decimal
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.widgets import Slider
import datetime


CONST_TIME_DIGIT = 1000


"""
timeString 은 1511836300.278119858 와 같은 형식의 시간 String
앞의 CONST_TIME_DIGIT 만큼의 자릿수 이상의 숫자를 자르고 반환합니다
e.g 1511836300.278119858  -> 300.278119858
"""
def getSimpleNumberFromTime(timeString):
    simple_time = Decimal(timeString)
    temp = int(simple_time/CONST_TIME_DIGIT)
    simple_time = simple_time - temp*CONST_TIME_DIGIT
    simple_time = int(simple_time*10000000000)
    print(simple_time)
    return simple_time;


def getDataTimeFromFloatString(timeString):
    return datetime.datetime.fromtimestamp(
        float(timeString)
    ).strftime('%Y-%m-%d %H:%M:%S.%f')


print(getDataTimeFromFloatString("1511836367.231953949"))

x_all_value = [] # x 축
y_all_value = []
contents = []

filename = "mongod_start_insert_find_kill_origin.txt"

f = open(filename, "r") # file 열기


fig1 = plt.figure(1)

ax1 = plt.subplot(211) # e.g 121 -> 1x2 matrix 중에 1
points_with_annotation = []
line_number = 0 ;

while True:
    line_number = line_number +1
    line = f.readline().split() # 한 줄씩 읽습니다. 공백을 기준으로 line[] 배열에 문자열들을 차례로 저장합니다.
    if not line: # 더이상 line 이 없으면 반복문을 종료
        break
    # 그래프에 쓸 x축과 y축을 결정합니다
    if len(line) >= 10:
        y_value_thread_id = int(line[5], 16) # thread id hex number 를 -> int 숫자로 변경
        # 아래는 String value
        time = line[0]
        interval = line[1]
        process_name = line[2]
        operation = line[6]
        data_size = line[7]
        is_socket = line[9]
        file_descriptor = line[8]

        annotation_description = operation + ", \n"
        if is_socket == "NON_SOCKET" :
            if len(line) >= 11 :
                descriptor_path = line[10]
                annotation_description += descriptor_path + ", \n"
            if len(line) >= 12 :
                data_content = line[11:]
                annotation_description += "".join(data_content) + ", \n"

        else: #socket io 일 경우
            if len(line) >= 12:
                socket_from = "" + line[10] + ":" + line[11]
                annotation_description += socket_from + " <-> "
            if len(line) >= 14:
                socket_to = "" + line[12] + ":" + line[13]
                annotation_description += socket_to + ", \n"
            if len(line) >= 15:
                data_content = line[14:]
                annotation_description += "".join(data_content) + ", \n"




        if line_number <10 : #10 줄만 출력해봅시다
            print(annotation_description)

        #전체 x, y 값 배열
        x_all_value.append(line_number)
        y_all_value.append(y_value_thread_id)

        # operation 인지에 따라 y 값의 색상 및 모양 달리 표현
        if "write" in line[6]:
            point, = plt.plot(line_number, y_value_thread_id, 'ro', ms=7, lw=1, alpha=0.5, mfc='red')

        elif "read" in line[6]:
            point, = plt.plot(line_number, y_value_thread_id,  'bo',  ms=7, lw=1, alpha=0.5, mfc='blue')

        elif "send" in line[6]:
            point, = plt.plot(line_number, y_value_thread_id, 'y>', ms=7, lw=1, alpha=0.5, mfc='orange')

        elif "recv" in line[6]:
            point, = plt.plot(line_number, y_value_thread_id,  'g>',  ms=7, lw=1, alpha=0.5, mfc='green')
        else:
            point, = plt.plot(line_number, y_value_thread_id, 'yo', ms=7, lw=1, alpha=0.7, mfc='yellow')

        print(fig1.get_size_inches() * fig1.dpi )

        # annotation
        # see: https://stackoverflow.com/questions/11537374/matplotlib-basemap-popup-box
        annotation = ax1.annotate(annotation_description,  # annotation message
                                  xy=(line_number, y_value_thread_id), # annotation 화살표포함 location  => scatter 위치를 가르켜 주어야 함
                                  xycoords='data',
                                  xytext=(line_number-3, y_value_thread_id+15000000),  # text 표시 위치
                                  textcoords='data',
                                  horizontalalignment="left",
                                  # arrowprops=dict(arrowstyle="simple", connectionstyle="arc3,rad=0"),  # 화살표 스타일
                                  bbox=dict(boxstyle="round", facecolor="w", edgecolor="0.5", alpha=0.9)
                                  )
        # by default, disable the annotation visibility
        annotation.set_visible(False)
        points_with_annotation.append([point, annotation])

f.close()


def on_move(event):
    visibility_changed = False
    for point, annotation in points_with_annotation:
        should_be_visible = (point.contains(event)[0] == True)

        if should_be_visible != annotation.get_visible():
            visibility_changed = True
            annotation.set_visible(should_be_visible)

    if visibility_changed:
        plt.draw()

on_move_id = fig1.canvas.mpl_connect('motion_notify_event', on_move)
plt.grid()


#전체 차트
ax2 = plt.subplot(212)
plt.plot(x_all_value, y_all_value, '-o', ms=7, lw=1, alpha=0.7, mfc='red')
plt.grid()



axcolor = 'lightgoldenrodyellow'
axpos = plt.axes([0.1, 0.01, 0.80, 0.03], axisbg=axcolor) # scroll 의 위치 [figure 창에서 가로시작 위치 비율, 세로시작 위치 비율, 가로 크기 비율 , 세로 크기 비율]
spos = Slider(axpos, 'Scroll', 0.0, 700.0) # scroll 범위

def update(val):
    pos = spos.val
    min_y_value = min(y_all_value)
    max_y_value = max(y_all_value)
    range = max_y_value - min_y_value;
    #범위를 위아래로 10분의 1씩 더 늘려줍니다
    min_y_value = min_y_value - range/10
    max_y_value = max_y_value + range/10
    ax1.axis([pos, pos+50, min_y_value, max_y_value]) # 한 화면에서 스크롤 양 옆 범위 / 위 아래 최소 최대 값
    ax2.axis([pos, pos+50, min_y_value, max_y_value]) # 한 화면에서 스크롤 양 옆 범위 / 위 아래 최소 최대 값
    plt.figure(1).canvas.draw_idle()

spos.on_changed(update)

plt.show() # 팝업 화면에 차트 띄우기




# ========== make visualization ========== #

# plt.figure(1)
#
# ax1 = plt.subplot(211) # e.g 121 -> 1x2 matrix 중에 1
# # plt.plot(x_write_time, y_write_operation, 'ro', x_read_time, y_read_operation, 'bo', x_etc_time, y_etc_operation, 'yo')  # x 축을 지정하지 않으면 원소 갯수 만큼이 x 축으로 지정됨
# plt.plot(x_write_time, y_write_operation, 'ro', ms=7, lw=1, alpha=0.5, mfc='red')
# plt.plot(x_read_time, y_read_operation, 'bo',  ms=7, lw=1, alpha=0.5, mfc='blue')
# plt.plot(x_etc_time, y_etc_operation, 'yo',  ms=7, lw=1, alpha=0.7, mfc='yellow')
# plt.grid()
#
# ax2 = plt.subplot(212)
# plt.plot(x_all_time, y_all_value, '-o', ms=7, lw=1, alpha=0.7, mfc='red')
# plt.grid()
#
#
# make scrollable
# see: https://stackoverflow.com/questions/31001713/plotting-the-data-with-scrollable-x-time-horizontal-axis-on-linux
#
# axcolor = 'lightgoldenrodyellow'
# axpos = plt.axes([0.1, 0.01, 0.80, 0.03], axisbg=axcolor) # scroll 의 위치 [figure 창에서 가로시작 위치 비율, 세로시작 위치 비율, 가로 크기 비율 , 세로 크기 비율]
# spos = Slider(axpos, 'Scroll', 0.0, 700.0) # scroll 범위
#
# def update(val):
#     pos = spos.val
#     min_y_value = min(y_all_value)
#     max_y_value = max(y_all_value)
#     range = max_y_value - min_y_value;
#     #범위를 위아래로 10분의 1씩 더 늘려줍니다
#     min_y_value = min_y_value - range/10
#     max_y_value = max_y_value + range/10
#     ax1.axis([pos, pos+50, min_y_value, max_y_value]) # 한 화면에서 스크롤 양 옆 범위 / 위 아래 최소 최대 값
#     ax2.axis([pos, pos+50, min_y_value, max_y_value]) # 한 화면에서 스크롤 양 옆 범위 / 위 아래 최소 최대 값
#     plt.figure(1).canvas.draw_idle()
#
# spos.on_changed(update)
#
# plt.show() # 팝업 화면에 차트 띄우기






# ========== line format ========== #

# [0] 1511836300.278119858 (시간)
# [1] 0.000003861 (소요 시간)
# [2] mongod (process name)
# [3] triton8 (os name)
# [4] 10007 (process id)
# [5] 7fdc20afed00 (thread id)
# [6] read (function name)
# [7] 16 (read/write data size)
# [8] 5 (file descriptor)
# [9] NON_SOCKET (socket or nonsocket )
# [10] /proc/10007/auxv (file descriptor)
# [11] !............... (read/write contents)

