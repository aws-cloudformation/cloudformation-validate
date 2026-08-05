/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const __wbg_wasmcelengine_free: (a: number, b: number) => void;
export const __wbg_wasmregoengine_free: (a: number, b: number) => void;
export const __wbg_wasmschemavalidator_free: (a: number, b: number) => void;
export const __wbg_wasmsemanticmodel_free: (a: number, b: number) => void;
export const init: () => void;
export const version: () => [number, number];
export const wasmcelengine_engineName: (a: number) => [number, number];
export const wasmcelengine_listRules: (a: number) => [number, number, number];
export const wasmcelengine_new: (a: any) => [number, number, number];
export const wasmcelengine_validateDetailed: (
    a: number,
    b: number,
    c: number,
    d: any,
    e: number,
    f: number,
) => [number, number, number];
export const wasmcelengine_validateStandard: (
    a: number,
    b: number,
    c: number,
    d: any,
    e: number,
    f: number,
) => [number, number, number];
export const wasmregoengine_engineName: (a: number) => [number, number];
export const wasmregoengine_listRules: (a: number) => [number, number, number];
export const wasmregoengine_new: (a: any) => [number, number, number];
export const wasmregoengine_validateDetailed: (
    a: number,
    b: number,
    c: number,
    d: any,
    e: number,
    f: number,
) => [number, number, number];
export const wasmregoengine_validateStandard: (
    a: number,
    b: number,
    c: number,
    d: any,
    e: number,
    f: number,
) => [number, number, number];
export const wasmschemavalidator_listRules: (a: number) => [number, number, number];
export const wasmschemavalidator_new: (a: any) => [number, number, number];
export const wasmschemavalidator_schemaCount: (a: number) => number;
export const wasmschemavalidator_validate: (a: number, b: number, c: number, d: number) => [number, number, number];
export const wasmsemanticmodel_conditions: (a: number) => [number, number, number];
export const wasmsemanticmodel_description: (a: number) => [number, number];
export const wasmsemanticmodel_formatVersion: (a: number) => [number, number];
export const wasmsemanticmodel_outputs: (a: number) => [number, number, number];
export const wasmsemanticmodel_parameters: (a: number) => [number, number, number];
export const wasmsemanticmodel_parse: (a: number, b: number) => [number, number, number];
export const wasmsemanticmodel_resources: (a: number) => [number, number, number];
export const wasmsemanticmodel_sourceLocation: (a: number, b: number, c: number) => [number, number, number];
export const wasmsemanticmodel_toDiagnosticModel: (a: number) => [number, number, number];
export const wasmsemanticmodel_transforms: (a: number) => [number, number, number];
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;
