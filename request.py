import requests



#headers = {'UserAPI-Key': API_KEY}

#response = requests.get('http://192.168.2.119:8000/uploadF/CC:50:E3:99:F9:D8')
# response = requests.get('http://192.168.2.119:8000/uploadF/CC:50:E3:99:F9:D8')

# print(response.text)

# response = requests.get('http://192.168.2.119:8000/uploadFS/CC:50:E3:99:F9:D8')

# print(response.text)

response = requests.get('http://192.168.1.165:8000/id/CC:50:E3:99:F9:D8/project/RTLS')

print(response.text)