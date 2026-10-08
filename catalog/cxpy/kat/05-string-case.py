s = 'The quick brown Fox'
print(s.upper(), '|', s.lower(), '|', len(s), s.title(), s.swapcase(), s.find('quick'), 'Fox' in s, s[-1])
print(' '.join(w.capitalize() for w in s.split()), 'abc'.rjust(6, '*'), 'hello'[::-1], ord('H'), 'ß'.upper())
