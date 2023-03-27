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
        template = "https://quickchart.io/chart/render/zm-c49b33bb-40d7-4b44-9e1a-05a9d9ccb9b5"
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
        BASE = "https://quickchart.io/chart/render/zm-a0c204c7-784e-40ff-9683-44a0c2e34f4c"
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