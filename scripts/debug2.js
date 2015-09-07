
/*
 * Run with:
 * frida.exe CivilizationV_DX11.exe -l C:\Users\Lasath\Documents\GitHub\itchy-weasel\scripts\debug2.js
 */

console.log("Starting Trace...");

var cvModule = Process.findModuleByName("CvGameCoreDLLFinal Release.dll");

function bind() {
	console.log("Found Module: " + cvModule.name);

	threadProbe();
	gameStateBind();
}

function gameStateBind() {
	var entryPoint = Module.findExportByName(cvModule.name, "DllGetGameContext");
	var getGameState = new NativeFunction(entryPoint, 'pointer', []);
	var gameState = getGameState();

	var vtable = Memory.readPointer(gameState);
	console.log("Found ICvGameContext1 at " + vtable);

	for (var i = 0; i < 65; i++) {
		var fn = Memory.readPointer(vtable.add(Process.pointerSize * i));
		console.log("\tFound method: " + DebugSymbol.fromAddress(fn).name + "()");
	}
}

// this is probably not worth it, since the DLL only exports 1 entry point.
function exportBind() {
	console.log("Binding to all exports...");
	Module.enumerateExports(cvModule.name, {
		onMatch: function(exp) {
			if (exp.type === "function") {
				console.log(exp.name + ": " + exp.address);
				Interceptor.attach(exp.address, {
					onEnter: function(args) {
						console.log("Entering function " + exp.name + "()");
					},
					onLeave: function(retval) {
						console.log(exp.name + ": retval = " + retval);
					}
				});
			}
		},
		onComplete: function() {
			console.log("Export binding complete.");
		}
	});
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