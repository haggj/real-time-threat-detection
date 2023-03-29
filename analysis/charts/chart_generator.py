from io import BytesIO

import requests
from PIL import Image

"""
API:
https://quickchart.io/chart/render/<id>

Edit:
https://quickchart.io/chart-maker/edit/<id>
"""

def save_image(image, filename):
    """Store image on file system"""
    with open(filename, "wb") as f:
        f.write(image)

def show_image(image):
    """Show image using Pillow"""
    img = Image.open(BytesIO(image))
    img.show()

class VerticalBarChart:
    @staticmethod
    def render(label, data, filename=None, show=None):
        template = "https://quickchart.io/chart/render/zm-73e8fb5b-c54c-465d-9139-86b308c87122"
        params = {
            "data1": ",".join([str(val) for val in data]),
            "labels": ",".join(label)
        }
        response = requests.get(template, params)
        assert response.ok, "Error requesting quickchart API"

        if show:
            show_image(response.content)

        if filename:
            save_image(response.content, filename)

        return response.content

class PieChart:

    @staticmethod
    def render(label, data, filename=None, show=None):
        BASE = "https://quickchart.io/chart/render/zm-f451639b-d854-4e3f-b3f6-f2dbdb7f0aa6"
        params = {
            "data1": ",".join([str(val) for val in data]),
            "labels": ",".join(label)
        }
        response = requests.get(BASE, params)
        assert response.ok, "Error requesting quickchart API"

        if show:
            show_image(response.content)

        if filename:
            save_image(response.content, filename)

        return response.content


if __name__ == "__main__":
    VerticalBarChart.render(["a", "b"], [10, 30], show=True)
    PieChart.render(["a","b"], [20,80], show=True)