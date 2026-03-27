import math
import json
import requests # type: ignore

def calculate_circle_area(radius):
    """A standard mathematical function."""
    return math.pi * (radius ** 2)

def fetch_weather(city):
    """A legitimate network call to a known API."""
    url = f"https://api.weather-service.com/data?q={city}"
    try:
        response = requests.get(url, timeout=5)
        return response.json()
    except:
        return {"error": "service unavailable"}

if __name__ == "__main__":
    area = calculate_circle_area(10)
    weather = fetch_weather("New York")
    print(f"Area: {area}, Weather: {weather}")
