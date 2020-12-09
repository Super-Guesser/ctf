#!/bin/env python3

from string import ascii_uppercase as UC
from random import SystemRandom
from enigma.machine import EnigmaMachine
from secretstuff import FLAG, PLUGBOARD_SETTINGS

assert FLAG.isupper() # Without pbcft{...}
random = SystemRandom()

for _ in range(50):
    ROTORS = [random.choice(("I","II","III","IV","V","VI","VII","VIII")) for _ in range(3)]
    REFLECTOR = random.choice(("B", "C", "B-Thin", "C-Thin"))
    RING_SETTINGS = [random.randrange(26) for _ in range(3)]

    machine = EnigmaMachine.from_key_sheet(
           rotors=ROTORS,
           reflector=REFLECTOR,
           ring_settings=RING_SETTINGS,
           plugboard_settings=PLUGBOARD_SETTINGS)

    machine.set_display(''.join(random.sample(UC, 3)))

    ciphertext = machine.process_text(FLAG)

    print(ciphertext)