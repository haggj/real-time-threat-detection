from log_analyzer import HttpsAnalyzer, SSHAnalyzer, HttpAnalyzer

import matplotlib.pyplot as plt
import numpy as np
import time

class ChartGenerator:
    def __init__(self, save_png_files: bool):
        self.httpsAnalyzer = HttpsAnalyzer()
        self.sshAnalyzer = SSHAnalyzer()
        self.httpAnalyzer = HttpAnalyzer()

        total_requests = {
            'http-80': self.httpAnalyzer.total_connections(),
            'https-443': self.httpsAnalyzer.total_connections(),
            'ssh-22': self.sshAnalyzer.total_connections()
        }

        ips = {
            'total_ips': [self.httpAnalyzer.total_connections(), self.httpsAnalyzer.total_connections(),self.sshAnalyzer.total_connections()],
            'unique_ips': [self.httpAnalyzer.unique_ips(), self.httpsAnalyzer.unique_ips(), self.sshAnalyzer.unique_ips()],
        }

        self.generate_pie_chart(total_requests, 'total_requests_pie', save_png_files)
        self.generate_bar_plot(total_requests, 42, 'total_requets_bar', save_png_files)
        self.generate_bar_plot_compare_horizontal(ips, ['http-80', 'https-443', 'ssh-22'], 'ips', save_png_files)

    def generate_pie_chart(self, values: dict, title: str, save_as_png: bool):
        labels = []
        sizes = []
        explode = []
        for key in values.keys():
            labels.append(key)
            sizes.append(values[key])
            explode.append(0.05)

        fig, ax = plt.subplots()
        ax.pie(sizes, explode=explode, labels=labels, autopct='%1.1f%%', shadow=True, startangle=90)
        plt.suptitle(title)
        if save_as_png:
            filePath = 'analyzer_plots/' + title + "-" + time.strftime("%Y%m%d-%H%M%S") + '.png'
            plt.savefig(filePath)
        plt.show()
        plt.clf()

    def generate_bar_plot(self, values: dict, threshold: int, title: str, save_as_png: bool):
        x = []
        y = []
        for key in values.keys():
            x.append(key)
            y.append(values[key])

        plt.bar(x, y)
        plt.axhline(y=threshold, xmin=0, xmax=1, color='red', linestyle='--')
        plt.xlabel("??")
        plt.ylabel("???")
        plt.suptitle(title)
        if save_as_png:
            filePath = 'analyzer_plots/' + title + "-" + time.strftime("%Y%m%d-%H%M%S") + '.png'
            plt.savefig(filePath, dpi=300, bbox_inches='tight')
        plt.show()
        plt.clf()

    def generate_bar_plot_compare_horizontal(self, values: dict, labels: list, title: str, save_as_png: bool):
        x = np.arange(3)  # the label locations
        width = 0.25  # the width of the bars
        multiplier = 0

        fig, ax = plt.subplots(layout='constrained')

        for key, value in values.items():
            offset = width * multiplier
            rects = ax.barh(x + offset, value, width, label=key)
            ax.bar_label(rects, padding=3)
            multiplier += 1

        # Add some text for labels, title and custom x-axis tick labels, etc.
        ax.set_ylabel('??')
        ax.set_title(title)
        ax.set_yticks(x + (width / 2), labels)
        ax.invert_yaxis()  # labels read top-to-bottom
        ax.legend(loc='upper left', ncols=3)
        # ax.set_ylim(0, 250)

        if save_as_png:
            filePath = 'analyzer_plots/' + title + "-" + time.strftime("%Y%m%d-%H%M%S") + '.png'
            plt.savefig(filePath, dpi=300, bbox_inches='tight')
        plt.show()
        plt.clf()

cg = ChartGenerator(False)