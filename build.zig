const std = @import("std");
const builtin = @import("builtin");

const pkgs = struct {
    const thread_pool = std.build.Pkg{
        .name = "thread_pool.zig",
        .path = std.build.FileSource.relative("./deps/zap/src/thread_pool.zig"),
    };
    const kybik = std.build.Pkg{
        .name = "framework.zig",
        .path = std.build.FileSource.relative("./deps/kybik-core/framework.zig"),
    };
};
pub fn build(b: *std.build.Builder) void {

    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("core", "src/main.zig");
    exe.addPackage(pkgs.thread_pool);
    exe.addPackage(pkgs.kybik);
    exe.linkLibC();
    exe.setTarget(target);
    exe.setBuildMode(mode);
    //exe.strip = true;
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);
    exe_tests.linkLibC();
    exe_tests.addPackage(pkgs.thread_pool);
    exe_tests.addPackage(pkgs.kybik);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);
}
