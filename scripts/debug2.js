
/*
 * Run with:
 * frida.exe CivilizationV_DX11.exe -l C:\Users\Lasath\Documents\GitHub\itchy-weasel\scripts\debug2.js
 */

console.log("Starting Trace...");

var cvModule = Process.findModuleByName("CvGameCoreDLLFinal Release.dll");

function bind() {
	console.log("Found Module: " + cvModule.name);

	threadProbe();
}

function threadProbe() {
	console.log("Probing threads...");
	Process.enumerateThreads({
		onMatch: function(thread) {
			console.log("\tFound thread " + thread.id + ", currently " + thread.state);
		},
		onComplete: function() {
			console.log("Thread probe complete.");
		}
	});

	console.log("Currently active thread is " + Process.getCurrentThreadId());
}

bind();