import re
text = 'Contact: ada@example.com, linus@kernel.org; phone +44 20 7946 0958.'
print(re.findall(r'[\w.]+@[\w.]+\.\w+', text), bool(re.fullmatch(r'\d{3}-\d{4}', '555-0100')), text.find('phone'))
m = re.search(r'(\+\d+) (\d+) (\d+) (\d+)', text)
print(m.group(0), m.start(), '|'.join(m.groups()), bool(re.search(r'colou?r', 'COLOR', re.I)))
