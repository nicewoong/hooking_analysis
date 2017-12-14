# import matplotlib.pyplot as plt
# import numpy as np
# import mpld3
#
# fig, ax = plt.subplots(subplot_kw=dict(axisbg='#EEEEEE'))
# N = 100
#
# scatter = ax.scatter(np.random.normal(size=N),
#                      np.random.normal(size=N),
#                      c=np.random.random(size=N),
#                      s=1000 * np.random.random(size=N),
#                      alpha=0.3,
#                      cmap=plt.cm.jet)
# ax.grid(color='white', linestyle='solid')
#
# ax.set_title("Scatter Plot (with tooltips!)", size=20)
#
# labels = ['point {0}'.format(i + 1) for i in range(N)]
# tooltip = mpld3.plugins.PointLabelTooltip(scatter, labels=labels)
# mpld3.plugins.connect(fig, tooltip)
#
# mpld3.show()

# import matplotlib.pyplot as plt
# import numpy as np
# import mplcursors
# np.random.seed(42)
#
# fig, ax = plt.subplots()
# ax.scatter(*np.random.random((2, 26)))
# ax.set_title("Mouse over a point")
#
# mplcursors.cursor(hover=True)
#
# plt.show()

# from matplotlib.pyplot import figure, show
# import numpy as npy
# from numpy.random import rand
#
#
# if 1: # picking on a scatter plot (matplotlib.collections.RegularPolyCollection)
#
#     x, y, c, s = rand(4, 100)
#     def onpick3(event):
#         ind = event.ind
#         print ('onpick3 scatter:', ind, npy.take(x, ind), npy.take(y, ind) )
#
#     fig = figure()
#     ax1 = fig.add_subplot(111)
#     col = ax1.scatter(x, y, 100*s, c, picker=True)
#     #fig.savefig('pscoll.eps')
#     fig.canvas.mpl_connect('pick_event', onpick3)
#
# show()
#
# import matplotlib.pyplot as plt
# import numpy as np; np.random.seed(1)
#
# x = np.random.rand(15)
# y = np.random.rand(15)
# names = np.array(list("ABCDEFGHIJKLMNO"))
# c = np.random.randint(1,5,size=15)
#
# norm = plt.Normalize(1,4)
# cmap = plt.cm.RdYlGn
#
# fig,ax = plt.subplots()
# sc = plt.scatter(x,y,c=c, s=100, cmap=cmap, norm=norm)
#
# annot = ax.annotate("", xy=(0,0), xytext=(20,20),textcoords="offset points",
#                     bbox=dict(boxstyle="round", fc="w"),
#                     arrowprops=dict(arrowstyle="->"))
# annot.set_visible(False)
#
# def update_annot(ind):
#
#     pos = sc.get_offsets()[ind["ind"][0]]
#     annot.xy = pos
#     text = "{}, {}".format(" ".join(list(map(str,ind["ind"]))),
#                            " ".join([names[n] for n in ind["ind"]]))
#     annot.set_text(text)
#     annot.get_bbox_patch().set_facecolor(cmap(norm(c[ind["ind"][0]])))
#     annot.get_bbox_patch().set_alpha(0.4)
#
#
# def hover(event):
#     vis = annot.get_visible()
#     if event.inaxes == ax:
#         cont, ind = sc.contains(event)
#         if cont:
#             update_annot(ind)
#             annot.set_visible(True)
#             fig.canvas.draw_idle()
#         else:
#             if vis:
#                 annot.set_visible(False)
#                 fig.canvas.draw_idle()
#
# fig.canvas.mpl_connect("motion_notify_event", hover)
#
# plt.show()

# import matplotlib.pyplot as plt
# from mpldatacursor import datacursor
# import random
#
# fig, ax = plt.subplots()
# ax.set_title('Click on a dot to display its label')
#
# # Plot a number of random dots
# for i in range(1, 1000):
#     ax.scatter([random.random()], [random.random()], label='$ID: {}$'.format(i))
#
# # Use a DataCursor to interactively display the label for a selected line...
# datacursor(formatter='{label}'.format)
#
# plt.show()


import matplotlib.pyplot as plt

fig = plt.figure()
ax = plt.axes()


points_with_annotation = []
for i in range(10):
    point, = plt.plot(i, i, 'o', markersize=10)

    annotation = ax.annotate("Mouseover point %s" % i, # annotation message
                             xy=(i, i),  # annotation location  => scatter 위치를 가르켜 주어야 함
                             xycoords='data',
                             xytext=(i + 0.5, i),
                             textcoords='data',
                             horizontalalignment="left",
                             arrowprops=dict(arrowstyle="simple", connectionstyle="arc3,rad=0"),
                             bbox=dict(boxstyle="round", facecolor="w", edgecolor="0.5", alpha=0.9)
        )
    # by default, disable the annotation visibility
    annotation.set_visible(False)

    points_with_annotation.append([point, annotation])


def on_move(event):
    visibility_changed = False
    for point, annotation in points_with_annotation:
        should_be_visible = (point.contains(event)[0] == True)

        if should_be_visible != annotation.get_visible():
            visibility_changed = True
            annotation.set_visible(should_be_visible)

    if visibility_changed:
        plt.draw()

on_move_id = fig.canvas.mpl_connect('motion_notify_event', on_move)

plt.show()
