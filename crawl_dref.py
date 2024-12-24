import requests
from bs4 import BeautifulSoup
import os 

# Base URL for Wireshark Display Filter References
base_url = 'https://www.wireshark.org/docs/dfref/'

# Access the URL to obtain the corresponding HTML file
response = requests.get(base_url)

# Parse the HTML file
soup = BeautifulSoup(response.content, 'html.parser')

# Directory to store Wireshark Display Filter References
save_dir = './dfref'
os.makedirs(save_dir, exist_ok=True)

# find all links in the HTML file
links = soup.find_all('a', href=True)
for link in links:
    href = link['href']
    if href.endswith('.html') and not href.startswith('..') and not href.startswith('http'):
        file_url = base_url + href
        
        file_response = requests.get(file_url)
        
        # obtain the filename and save the file
        file_name = os.path.join(save_dir, href)
        os.makedirs(os.path.dirname(file_name), exist_ok=True)
        with open(file_name, 'wb') as file:
            file.write(file_response.content)
        print(f'Saved: {file_name}')
        
print(f'Wireshark Display Filter References are stored in {save_dir}.')