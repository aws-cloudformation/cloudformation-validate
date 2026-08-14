import { defineConfig } from 'vitest/config';

export default defineConfig({
    root: '..',
    test: {
        include: ['tests/**/*.test.ts'],
        testTimeout: 120_000,
        hookTimeout: 120_000,
        teardownTimeout: 120_000,
        fileParallelism: false,
        coverage: {
            provider: 'v8',
            include: ['dist/**/*.js'],
            exclude: ['dist/package.json'],
            reporter: ['text', 'lcov', 'json-summary'],
            reportsDirectory: 'tests/coverage',
            reportOnFailure: true,
        },
    },
});
