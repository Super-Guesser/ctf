# Ghost writer
The audio file contains 275 key presses, divided by complete silence, with each unique key having a constant sound. Extract the single keystrokes by splitting the audio at the silence, and assign letters to each unique keypress. Use a substitution solver to recover the right plaintext.

```python
import wave
from collections import Counter

wr = wave.open('output.wav')
frames = wr.readframes(wr.getnframes()-1)

n = frames.split(frames[:100])[1:-1]

f = ' etaoinshrdlcumwfgypbvkjxqz'
d = {}
for i, (v, _) in enumerate(Counter(n).most_common()):
    d[v] = f[i]

print(''.join(d[x] for x in n))
```

Recover the right text with a [substitution solver](https://www.guballa.de/substitution-solver).
```
the day had begun on a bright note the sun finally peeled through the rain for the first time in a week and the flag is pbctf open brace mechanical keyboards are loud close brace and the birds were singing in its warmth there was no way to anticipate what was about to happen
```
The flag is `pbctf{mechanical_keyboards_are_loud}`
