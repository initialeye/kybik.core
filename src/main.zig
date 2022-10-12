const std = @import("std");
const Fw = @import("framework.zig");
const Lib = @import("corelib.zig");

const Map = std.ArrayHashMapUnmanaged;
const Vector = std.ArrayListUnmanaged;

pub const StringMapContext = struct {
    pub fn hash(self: StringMapContext, name: []const u8) u32 {
        _ = self;
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHashStrat(&hasher, name, .Deep);
        return @truncate(u32, hasher.final());
    }

    pub fn eql(self: StringMapContext, a: []const u8, b: []const u8) bool {
        _ = self;
        return std.mem.eql(u8, a, b);
    }
};

const ModuleImpl = struct {
    const Signals = Map([]const u8, Signal, StringMapContext, true);

    dynlib: std.DynLib,
    gpa: std.heap.GeneralPurposeAllocator(.{}),
    libpath: []const u8,
    respath: []const u8,
    logprefix: []const u8,
    header: *const Fw.ModuleHeader,
    signals: Signals,
    loglvl: Fw.LogLevel = Fw.LogLevel.MainInfo,

    fn convert(module: Fw.Module) *ModuleImpl {
        return @ptrCast(*ModuleImpl, module);
    }
    fn create(core: *CoreImpl, path: []const u8) anyerror!ModuleImpl {
        var ret: ModuleImpl = undefined;
        ret.dynlib = std.DynLib.open(path) catch unreachable;
        ret.gpa = std.heap.GeneralPurposeAllocator(.{}){};
        const al = ret.gpa.allocator();
        ret.libpath = try al.dupe(u8, path[0..]);
        {
            const api = ret.dynlib.lookup(fn () usize, "API_version") orelse unreachable;
            if (api() != Fw.API_VERSION) unreachable;
        }
        {
            const load = ret.dynlib.lookup(fn (*const Fw.Core) *const Fw.ModuleHeader, "load") orelse unreachable;
            ret.header = load(core.interface);
            ret.logprefix = get_slice_from_array(ret.header.logp[0..]);
        }
        const respathParts = [_][] const u8 { core.root, "resources", get_slice_from_array(ret.header.dirn[0..]), };
        ret.respath = std.fs.path.join(al, respathParts[0..]) catch unreachable;
        ret.signals = .{};
        return ret;
    }
    fn destroy(this: *ModuleImpl) void {
        const al = this.gpa.allocator();
        al.free(this.libpath);
        al.free(this.respath);
        this.signals.deinit(this.gpa.allocator());
        const res = this.gpa.deinit();
        this.dynlib.close();
        std.debug.assert(!res);
    }
    fn allocator(this: *ModuleImpl) std.mem.Allocator {
        return this.gpa.allocator();
    }
    fn if_version(this: *const ModuleImpl) Fw.CompatVersion {
        return this.header.vers.compat();
    }
    fn if_name(this: *const ModuleImpl) []const u8 {
        return this.interface.get_name().from();
    }
    fn iterate_files(this: *ModuleImpl, path: []const u8, pattern: []const u8, cb: Fw.FileIterateCallback) void {
        const paths = [_][]const u8 { this.respath, path };
        const fullpath = std.fs.path.resolve(this.allocator(), paths[0..]) catch unreachable;
        defer this.allocator().free(fullpath);
        var dir = std.fs.cwd().openDir(fullpath, .{ .iterate = true }) catch unreachable;
        var it = dir.iterate();
        _ = pattern; //TODO
        while (it.next() catch unreachable) |file| {
            const internalPaths = [_][]const u8 { this.respath, path, file.name };
            const internalFullpath = std.fs.path.resolve(this.allocator(), internalPaths[0..]) catch unreachable;
            defer this.allocator().free(internalFullpath);
            cb(Fw.String.init(file.name), Fw.String.init(internalFullpath));
        }
    }
    fn register(this: *ModuleImpl, core: *CoreImpl, signame: []const u8) *const Signal {
        var sig = this.signals.getOrPut(this.gpa.allocator(), signame) catch unreachable;
        if (!sig.found_existing) {
            sig.value_ptr.* = Signal {
                .source = this,
                .core = core,
                .subs = .{},
                .name = signame,
            };
        }
        return sig.value_ptr;
    }
    fn subscribe(this: *ModuleImpl, signame: []const u8, handler: Fw.SubCallback) Signal.Errors!void {
        var sig = this.signals.getPtr(signame);
        if (sig == null) {
            return Signal.Errors.SubNotFound;
        }
        sig.?.subscribe(handler);
    }
};

const ThreadUtil = struct {
    const Args = struct{
        mod: *ModuleImpl,
        ctx: Fw.CbCtx,
        typ: union {
            sch: struct {
                cb: Fw.SchedCallback,
                expires: u64,
            },
            sub: struct {
                cb: Fw.SubCallback,
                nm: []const u8,
            }
        }
    };

    const Task = Lib.Task (Args, void);

    fn createSched(mod: *ModuleImpl, ccb: Fw.SchedCallback, timestamp: u64, ctx: Fw.CbCtx) *Task {
        const args = Args {
            .mod = mod,
            .typ = .{
                .sch = .{
                    .cb = ccb,
                    .expires = timestamp,
                },
            },
            .ctx = ctx
        };
        return Task.create(callbackSched, args, mod.allocator()) catch unreachable;
    }

    fn createSub(mod: *ModuleImpl, ccb: Fw.SubCallback, signame: []const u8, ctx: Fw.CbCtx) *Task {
        const args = Args {
            .mod = mod,
            .typ = .{
                .sub = .{
                    .cb = ccb,
                    .nm = signame,
                },
            },
            .ctx = ctx
        };
        return Task.create(callbackSub, args, mod.allocator()) catch unreachable;
    }

    fn lt(context: void, d1: *const ThreadUtil.Task, d2: *const ThreadUtil.Task) std.math.Order {
        _ = context;
        return std.math.order(d1.args.typ.sch.expires, d2.args.typ.sch.expires);
    }

    fn callbackSched(a: Args) void {
        return a.typ.sch.cb(a.ctx);
    }

    fn callbackSub(a: Args) void {
        return a.typ.sub.cb(Fw.String.init(a.typ.sub.nm), a.ctx);
    }
};

const Signal = struct {
    const Subs = Vector(Subscription);

    const Subscription = struct {
        cb: Fw.SubCallback,
    };

    source: *ModuleImpl,
    core: *CoreImpl,
    subs: Subs = .{},
    name: []const u8,

    fn emit(this: *const Signal, ctx: Fw.CbCtx) usize {
        for (this.subs.items) |sub| {
            this.core.emit(this.source, sub.cb, this.name, ctx);
        }
        return this.subs.items.len;
    }

    fn subscribe(this: *Signal, callback: Fw.SubCallback) void {
        var ptr = this.subs.addOne(this.source.gpa.allocator()) catch unreachable;
        ptr.* = Subscription {
            .cb = callback,
        };
    }

    const Errors = error {
        SubNotFound,
    };
};

const coreIface = Fw.Core {
    .exit =             Export.exit,
    .log =              Export.module_log,
    .get_allocator =    Export.get_allocator,
    .get_if =           Export.get_if,
    .get_if_specific =  Export.get_if_specific,
    .get_if_ver_num =   Export.get_if_ver_num,
    .get_if_ver_count = Export.get_if_ver_count,
    .get_if_count =     Export.get_if_count,
    .get_if_name =      Export.get_if_name,
    .get_resource_path = Export.get_resource_path,
    .subscribe =        Export.subscribe,
    .register =         Export.register,
    .emit =             Export.emit,
    .schedule_task =    Export.schedule_task,
    .iterate_files =    Export.iterate_files,
    .nanotime =         Export.nanotime,
};

var coreImpl: CoreImpl = undefined;

const CoreImpl = struct{
    const SchedQueue = std.PriorityQueue(*ThreadUtil.Task, void, ThreadUtil.lt);
    const ThreadPool = Lib.ThreadPool(ThreadUtil.Args, void);
    const ModMap = Map([]const u8, IfModules, StringMapContext, true);

    const IfModules = struct {
        selected: usize,
        list: Vector(ModuleImpl),
        
        fn get_selected(this: *IfModules) *ModuleImpl {
            return &this.list.items[this.selected];
        }
    };

    core: ModuleImpl = undefined,
    root: []const u8 = undefined,
    modules: ModMap = .{},
    timerQueue: SchedQueue = undefined,
    timer: std.time.Timer,
    tp: ThreadPool,
    mtx: std.Thread.Mutex = .{},
    interface: *const Fw.Core = &coreIface,
    running: bool = true,

    fn init() CoreImpl {
        const num_cpus = std.Thread.getCpuCount() catch unreachable;
        const num_threads = std.math.cast(u32, num_cpus) catch std.math.maxInt(u32);
        var impl = CoreImpl {
            .core = ModuleImpl {
                .dynlib = undefined,
                .gpa = std.heap.GeneralPurposeAllocator(.{}){},
                .libpath = ".",
                .respath = ".",
                .logprefix = "CORE",
                .header = undefined,
                .signals = .{},
            },
            .timer = std.time.Timer.start() catch unreachable,
            .tp = ThreadPool.init( .{ .stack_size = 0x400, .max_threads = num_threads } )
        };
        const paths = [_][]const u8 {std.mem.span(std.os.argv[0]), ".."};
        impl.root = std.fs.path.resolve(impl.core.allocator(), paths[0..]) catch unreachable;
        return impl;
    }

    fn deinit(this: *CoreImpl) void {
        const al = this.core.allocator();
        al.free(this.root);
        this.mtx.lock();
        defer this.mtx.unlock();
        this.tp.shutdown();
        this.tp.deinit();
        this.timerQueue.deinit();
        std.debug.assert(!this.core.gpa.deinit());
    }
    
    fn exit(this: *CoreImpl) void {
        this.running = false;
    }

    fn get_interface(this: *CoreImpl, ifname: []const u8, version: Fw.Version) ?*ModuleImpl {
        const modules = this.modules.getPtr(ifname);
        if (modules == null) {
            return null;
        }
        for (modules.?.list.items) |*elem| {
            if (elem.if_version().num() == version.num()) {
                return elem;
            }
        }
        return null;
    }

    fn get_module_current(this: *CoreImpl, ifname: []const u8) ?*ModuleImpl {
        const modules = this.modules.getPtr(ifname);
        if (modules == null) {
            return null;
        }
        return modules.?.get_selected();
    }

    fn get_modules(this: *CoreImpl, name: []const u8) ?[]ModuleImpl {
        const modules = this.modules.getPtr(name);
        if (modules == null) {
            return null;
        }
        return modules.?.list.items;
    }

    fn load_all(this: *CoreImpl, path: []const u8) void {
        const paths = [_][]const u8 { this.root, path };
        const libsPath = std.fs.path.resolve(this.core.allocator(), paths[0..]) catch unreachable;
        defer this.core.allocator().free(libsPath);
        var libs = std.fs.cwd().openDir(libsPath, .{ .iterate = true }) catch unreachable;
        var it = libs.iterate();
        while (it.next() catch unreachable) |n| {
            var buffer: [0x2000]u8 = undefined;
            const balloc = std.heap.FixedBufferAllocator.init(&buffer).allocator();
            if (!std.mem.eql(u8, std.fs.path.extension(n.name), ".so")) continue;
            const sopaths = [_][]const u8 { libsPath, n.name };
            const fullname = std.fs.path.resolve(balloc, sopaths[0..]) catch unreachable;
            this.load_one(fullname);
        }
    }

    fn load_one(this: *CoreImpl, fullpath: []const u8) void {
        const module = ModuleImpl.create(this, fullpath) catch unreachable;
        const coreAlloc = this.core.gpa.allocator();
        const ifName = module.header.intf.name.from();
        var putRes = this.modules.getOrPut(coreAlloc, ifName) catch unreachable;
        if (!putRes.found_existing) {
            putRes.value_ptr.* = IfModules {
                .selected = 0,
                .list = .{},
            };
        }
        var elem = putRes.value_ptr.list.addOne(coreAlloc) catch unreachable;
        elem.* = module;
    }

    fn unload_all(this: *CoreImpl) void {
        const coreAlloc = this.core.gpa.allocator();
        var iter = this.modules.iterator();
        while(iter.next()) |*entry| {
            for(entry.value_ptr.list.items) |*elem| {
                elem.destroy();
            }
            entry.value_ptr.list.deinit(this.core.gpa.allocator());
        }
        this.modules.deinit(coreAlloc);
    }

    fn unload_one(this: *CoreImpl, module: *ModuleImpl) void {
        _ = this;
        _ = module;
    }
    
    fn resolve_dependencies(this: *CoreImpl) void {
        var iter = this.modules.iterator();
        while(iter.next()) |*entry| {
            for(entry.value_ptr.list.items) |*elem| {
                const deps = elem.header.deps.from();
                for (deps) |*dep| {
                    const ifs = this.modules.get(dep.*.ifn.from()) orelse unreachable;
                    for (ifs.list.items) |*module| {
                        if (!dep.check(module.*.header.vers)) {
                            unreachable;
                        }
                        if (!elem.header.func.resolve_dependency(module.*.header)) unreachable;
                    }
                }
            }
            
        }
    }

    fn nanotime(this: *CoreImpl) u64 {
        return this.timer.read();
    }

    fn schedule(this: *CoreImpl, module: *ModuleImpl, callback: Fw.SchedCallback, timestamp: u64,
                ctx: Fw.CbCtx) void
    {
        if (this.running) {
            const elem = ThreadUtil.createSched(module, callback, timestamp, ctx);
            this.enqueue(elem);
        }
    }

    fn emit(this: *CoreImpl, module: *ModuleImpl, callback: Fw.SubCallback, signame: []const u8, ctx: Fw.CbCtx) void
    {
        if (this.running) {
            const elem = ThreadUtil.createSub(module, callback, signame, ctx);
            const batch = ThreadPool.Batch.from(elem);
            this.tp.schedule(batch);
        }
    }

    fn enqueue(this: *CoreImpl, task: *ThreadUtil.Task) void {
        this.mtx.lock();
        defer this.mtx.unlock();
        this.timerQueue.add(task) catch unreachable;
    }

    fn init_modules(this: *CoreImpl) void {
        coreImpl.timerQueue = SchedQueue.init(coreImpl.core.gpa.allocator(), .{});
        var iter = this.modules.iterator();
        while(iter.next()) |entry| {
            entry.value_ptr.get_selected().header.func.init(&coreIface, @ptrCast(Fw.Module, entry.value_ptr.get_selected()));
        }
        this.resolve_dependencies();
    }
    
    fn quit_modules(this: *CoreImpl) void {
        var iter = this.modules.iterator();
        while(iter.next()) |entry| {
            entry.value_ptr.get_selected().header.func.quit();
        }
    }

    fn run(this: *CoreImpl, loop: bool) void {
        var iter = this.modules.iterator();
        if (loop) {
            while(iter.next()) |entry| {
                entry.value_ptr.get_selected().header.func.run();
            }

            while(this.running or this.timerQueue.count() > 0) {
                var tim = this.timer.read();
                std.time.sleep(1);
                var task: ?*ThreadUtil.Task = undefined;
                var needProcess = false;
                {
                    this.mtx.lock();
                    defer this.mtx.unlock();
                    task = this.timerQueue.peek();
                    if (task != null and task.?.args.typ.sch.expires <= tim) {
                        needProcess = true;
                        _ = this.timerQueue.remove();
                    }
                }
                    if (needProcess) {
                        const elem = task.?;
                        elem.execute();
                        //const batch = ThreadPool.Batch.from(elem);
                        //this.tp.schedule(batch);
                    }
            }
        }
    }
};

const Export = struct {
    fn exit() callconv(.C) void {
        coreImpl.exit();
    }
    fn module_log(module: Fw.Module, level: Fw.LogLevel, msg: Fw.String) callconv(.C) void {
        const m = ModuleImpl.convert(module);
        if (@enumToInt(level) <= @enumToInt(m.loglvl)) {
            const lvlStr = switch (level) {
                .Critical     => "CRITICAL",
                .Error        => "ERROR",
                .Warning      => "WARNING",
                .MainInfo,
                .AdditionInfo => "INFO",
                .DebugLevel0,
                .DebugLevel1,
                .DebugLevel2,
                .DebugLevel3,
                .DebugLevel4  => "DEBUG",
            };
            std.debug.print("[{s}][{s}]:{s}\n", .{ m.logprefix, lvlStr, msg.from() });
        }
    }
    fn get_allocator(module: Fw.Module) callconv(.C) Fw.Allocator {
        var allocator = @ptrCast(*ModuleImpl, module).allocator();
        return .{
            .ptr = allocator.ptr,
            .vtable = allocator.vtable,
        };
    }
    fn get_if(name: Fw.String) callconv(.C) ?*const Fw.Interface {
        var mod = coreImpl.get_module_current(name.from()) orelse {
            return null;
        };
        return &mod.header.intf;
    }
    fn get_if_specific(name: Fw.String, version: Fw.Version) callconv(.C) ?*const Fw.Interface {
        var mod = coreImpl.get_interface(name.from(), version) orelse {
            return null;
        };
        return &mod.header.intf;
    }
    fn get_if_ver_num(name: Fw.String, num: usize) callconv(.C) ?*const Fw.Interface {
        var mods = coreImpl.get_modules(name.from());
        if (mods == null or mods.?.len >= num) {
            return null;
        }
        return &mods.?.ptr[num].header.intf;
    }
    fn get_if_ver_count(name: Fw.String) callconv(.C) usize {
        var mods = coreImpl.get_modules(name.from()) orelse {
            return 0;
        };
        return mods.len;
    }
    fn get_if_count() callconv(.C) usize {
        return coreImpl.modules.keys().len;
    }
    fn get_if_name(num: usize) callconv(.C) Fw.String {
        if (num >= get_if_count()) {
            return Fw.String.init("");
        }
        return Fw.String.init(coreImpl.modules.keys()[num]);
    }
    fn get_resource_path(module: Fw.Module) callconv(.C) Fw.String {
        const this = @ptrCast(*ModuleImpl, module);
        return Fw.String.init(this.respath);
    }
    fn subscribe(name: Fw.String, version: Fw.Version, signame: Fw.String, handler: Fw.SubCallback) callconv(.C) u8 {
        var mod = coreImpl.get_interface(name.from(), version);
        if (mod == null) {
            return @errorToInt(Signal.Errors.SubNotFound);
        }
        mod.?.subscribe(signame.from(), handler) catch |err| {
            return @errorToInt(err);
        };
        return 0;
    }
    fn register(module: Fw.Module, signame: Fw.String) callconv(.C) *const Fw.Signal {
        return @ptrCast(*const Fw.Signal, ModuleImpl.convert(module).register(&coreImpl, signame.from()));
    }
    fn emit(signal: *const Fw.Signal, ctx: Fw.CbCtx) callconv(.C) usize {
        return @ptrCast(*const Signal, @alignCast(@alignOf(*Signal), signal)).emit(ctx);
    }
    fn schedule_task(module: Fw.Module, callback: Fw.SchedCallback, timestamp: u64, ctx: Fw.CbCtx) callconv(.C) void {
        coreImpl.schedule(@ptrCast(*ModuleImpl, module), callback, timestamp, ctx);
    }
    fn iterate_files(module: Fw.Module, path: Fw.String, pat: Fw.String, cb: Fw.FileIterateCallback) callconv(.C) void {
        ModuleImpl.convert(module).iterate_files(path.from(), pat.from(), cb);
    }
    fn nanotime() callconv(.C) u64 {
        return coreImpl.nanotime();
    }
};

fn get_slice_from_array(inp: []const u8) []const u8 {
    for (inp) |n, i| {
        if (n == 0) {
            return inp[0..i];
        }
    }
    return inp;
}

pub fn main() void {
    coreImpl = CoreImpl.init();
    defer coreImpl.deinit();
    coreImpl.load_all("./libs/");
    defer coreImpl.unload_all();

    coreImpl.init_modules();
    defer coreImpl.quit_modules();
    coreImpl.run(true);
}

