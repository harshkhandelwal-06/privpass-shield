from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.passwords import analyze  # noqa: E402

CASES = [
    ('Name only', 'divymathur'),
    ('Name + year', 'divy1934'),
    ('Name + repeated numbers', 'divy1023divy1032'),
    ('Numeric only', '3492847592039485720'),
    ('Long predictable', 'aaaasfiefifosdnofsdfn'),
    ('Random-looking human text', 'asfajfbjadbfiwebfiwefiewb'),
    ('Passphrase', 'river lantern copper orbit'),
    ('Strong mixed human secret', 'idsfiwefi38y238@dbf1412314@fhiw&dfihwif*jcowjf^^^iqhfiwhef7&'),
    ('Generated secret', 'N7p#xQ2!mR8@zK4$uP6^wL9?cD3&fH5*'),
]

if __name__ == '__main__':
    for name, value in CASES:
        generated = name == 'Generated secret'
        result = analyze(value, [], generated=generated)
        print(f'{name:28} {result["score"]:>3}/100  {result["label"]:<9} {result["verdict"]:<6}')
