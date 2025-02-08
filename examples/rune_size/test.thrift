enum MapKey {
    A, B, C, D, E, F
}

struct Example {
    1: string Message (vt.max_rune_size = "20" vt.min_rune_size = "20") // length of Message should be greater than or equal to 30
    2: i32 ID (vt.ge = "10000") // ID must be greater than or euqal to 10000
    3: list<double> Values (vt.elem.gt = "0.25") // element of Values must be greater than 0.25
    4: map<MapKey, string> KeyValues (vt.key.defined_only = "true") // value of KeyValues key must be defined in MapKey
    5: map<string, string> KeyValues2 (vt.key.max_rune_size = "10" vt.key.min_rune_size = "10") // length of KeyValues2's key must be less than or equal to 10
}