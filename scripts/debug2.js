
/*
 * Run with:
 * frida.exe CivilizationV_DX11.exe -l C:\Users\Lasath\Documents\GitHub\itchy-weasel\scripts\debug2.js
 */

console.log("Starting Trace...");

function bind() {
	var cvGame = Process.findModuleByName("CvGameCoreDLLFinal Release.dll");
	console.log("Found Module: " + cvGame.name);

	console.log("Setting up interceptors...");
	Module.enumerateExports(cvGame.name, {
		onMatch: function(exp) {
			console.log(exp.name);
		},
		onComplete: function() {
			console.log("Finished setting up.")
		}
	});
}

bind();