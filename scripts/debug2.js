
/*
 * Run with:
 * frida.exe CivilizationV_DX11.exe -l C:\Users\Lasath\Documents\GitHub\itchy-weasel\scripts\debug2.js
 */

console.log("Starting Trace...");

var cvModule = Process.findModuleByName("CvGameCoreDLLFinal Release.dll");
const SYMBOL_PATTERNS = [
	"CvDllGameContext::*",
	"CvGame::*",
	"CvPreGame::*"
];

function bind() {
	console.log("Found Module: " + cvModule.name);

	threadProbe();
	// bindExports();
	// bindGameState();
	for (var x in SYMBOL_PATTERNS) {
		bindMatchingSymbols(SYMBOL_PATTERNS[x]);
	}
}

function bindMatchingSymbols(pattern) {
	var symbols = DebugSymbol.findFunctionsMatching(pattern);
	// var start = cvModule.base;
	// var end = start.add(cvModule.size);
	for (var i in symbols) {
		var addr = symbols[i];
		var method = DebugSymbol.fromAddress(addr);

		if (method.moduleName !== cvModule.name) {
			continue;
		}

		console.log(method.name);
		try {
			bindMethod(addr, method.name);
		} catch (e) {
			console.log(e.toString());
		}
	}
}

function bindGameState() {
	var entryPoint = Module.findExportByName(cvModule.name, "DllGetGameContext");
	var getGameState = new NativeFunction(entryPoint, 'pointer', []);
	var gameState = getGameState();

	// bindObject(gameState);

	var getPreGame_addr = DebugSymbol.getFunctionByName("CvDllGameContext::GetPreGame");
	var getPreGame = new NativeFunction(getPreGame_addr, 'pointer', ['pointer']);
	var preGame = getPreGame(gameState);
	console.log("got PreGame: " + preGame);
	bindObject(getPreGame(preGame));
}

function bindObject(address, name) {
	var vtable = Memory.readPointer(address);
	console.log("Found ICvGameContext1 at " + vtable);

	var i = 0;
	do {
		var fn = Memory.readPointer(vtable.add(Process.pointerSize * i));
		var method = DebugSymbol.fromAddress(fn);

		console.log("\tFound method: " + method.name + "()");
		try {
			bindMethod(fn, method.name);
		} catch (e) {
			console.log(e.toString());
		}

		i++;
	} while(method.moduleName === cvModule.name);
}

function bindMethod (address, name) {
	Interceptor.attach(address, {
		onEnter: function(args) {
			// console.log("Entering " + name + "() with:")
			console.log(args.length);
			for (var x in args) {
				console.log("\targ" + x + "=" + args[x]);
			}
		},
		onLeave: function(retval) {
			// console.log("Returning from " + name + "() with:");
			// console.log("\tretval=" + retval);
		}
	});
}

// this is probably not worth it, since the DLL only exports 1 entry point.
function bindExports() {
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