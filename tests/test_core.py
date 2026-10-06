from app.passwords import analyze


def test_name_is_not_strong():
    a = analyze('divymathur')
    assert a['score'] <= 35
    assert a['flags']['identity_like'] is True


def test_name_plus_year_is_weak():
    a = analyze('divy1934')
    assert a['score'] <= 35
    assert a['flags']['identity_like'] is True
    assert a['flags']['year'] is True


def test_long_numeric_is_weak():
    a = analyze('3492847592039485720')
    assert a['score'] <= 35
    assert a['flags']['digit_only'] is True


def test_long_predictable_is_weak():
    a = analyze('aaaasfiefifosdnofsdfn')
    assert a['score'] < 35
    assert any('pattern' in r.lower() or 'repeat' in r.lower() for r in a['reasons'])


def test_random_looking_human_text_is_not_perfect():
    a = analyze('asfajfbjadbfiwebfiwefiewb')
    assert a['score'] < 65
    assert a['flags']['letter_only'] if 'letter_only' in a['flags'] else True


def test_generated_secret_is_high():
    a = analyze('N7p#xQ2!mR8@zK4$uP6^wL9?cD3&fH5*', generated=True)
    assert a['score'] >= 92
    assert a['flags']['generated'] is True
    assert a['construction_bits'] is not None


def test_strong_generated_passphrase_is_high():
    a = analyze('river-lantern-copper-orbit-silver-zenith-falcon', generated=True)
    assert a['score'] >= 92
    assert a['construction_bits'] is not None


def test_name_with_space_is_still_identity_like():
    a = analyze('divy mathur')
    assert a['score'] <= 15
    assert a['flags']['identity_like'] is True


def test_complex_human_password_can_be_strong_without_being_perfect():
    a = analyze('idsfiwefi38y238@dbf1412314@fhiw&dfihwif*jcowjf^^^iqhfiwhef7&')
    assert 65 <= a['score'] < 93
    assert a['verdict'] == 'ACCEPT'


def test_password_model_calibration_examples():
    from app.passwords import analyze
    assert analyze('divymathur')['score'] < 20
    assert analyze('divy1934')['score'] < 30
    assert analyze('3492847592039485720')['score'] < 70
    assert analyze('river lantern copper orbit')['score'] >= 85
    assert analyze('idsfiwefi38y238@dbf1412314@fhiw&dfihwif*jcowjf^^^iqhfiwhef7&')['score'] >= 85
