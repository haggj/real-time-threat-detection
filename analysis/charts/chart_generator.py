from io import BytesIO

import requests
from PIL import Image

"""
API:
https://quickchart.io/chart/render/<id>

Edit:
https://quickchart.io/chart-maker/edit/<id>
"""

class VerticalBarChart:
    @staticmethod
    def render(label, data):
        template = "https://quickchart.io/chart/render/zm-24e4e523-3e27-40a5-b559-e33f80461eaa"
        params = {
            "data1": ",".join([str(val) for val in data]),
            "labels": ",".join(label)
        }
        response = requests.get(template, params)
        img = Image.open(BytesIO(response.content))
        img.show()

class PieChart:
    @staticmethod
    def render(label, data):
        BASE = "https://quickchart.io/chart/render/zm-b82a226a-3f63-4efb-b26a-c4007a69635a"
        params = {
            "data1": ",".join([str(val) for val in data]),
            "labels": ",".join(label)
        }
        print(params)
        response = requests.get(BASE, params)
        img = Image.open(BytesIO(response.content))
        img.show()


if __name__ == "__main__":
    VerticalBarChart.render(["a", "b"], [10, 30])
    PieChart.render(["a","b"], [20,80])