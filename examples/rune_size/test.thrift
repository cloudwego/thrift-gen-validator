struct Example {
    1: string MaxRuneString (vt.max_rune_size = "10") // rune length of MaxRuneString should be less than or equal to 10
    2: string MinRuneString (vt.min_rune_size = "10") // rune length of MinRuneString should be greater than or equal to 10
    3: map<string, string> KeyValues (vt.key.max_rune_size = "10" vt.key.min_rune_size = "10") // rune length of KeyValues' key must be equal to 10
}