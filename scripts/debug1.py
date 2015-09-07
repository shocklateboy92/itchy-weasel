#!/usr/bin/python

import frida

def findDll():
	s = frida.attach("CivilizationV_DX11.exe")
	for mod in s.enumerate_modules():
		if mod.name.startswith("Cv"):
			print(mod)

def dumpGame(file=False):
	s = frida.attach("CivilizationV_DX11.exe")
	print("Total segments: {}".format(len(s.enumerate_ranges('---'))))

	if file:
		print("Preparing to dump to '{}'.".format(file))
		with open(file, "wb") as f:
			for m in s.enumerate_ranges('---'):
				f.write(m)