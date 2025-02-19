mod kernel;

use std::ffi::{c_char, c_float, c_int, c_void, CStr, CString};
use std::{iter, mem, ptr};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::ptr::null_mut;
use std::sync::{Arc, LazyLock};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use d3d12::{Binding, Blob, CachedPSO, CmdListType, ComPtr, CommandAllocator, CommandList, CommandQueue, CommandQueueFlags, Debug, DescriptorHeap, DescriptorRange, DescriptorRangeType, Device, DxgiFactory, Event, Factory1, Factory4, FactoryCreationFlags, FeatureLevel, Fence, GraphicsCommandList, NodeMask, PipelineState, PipelineStateFlags, PipelineStateSubobject, Priority, Resource, RootParameter, RootSignature, Shader, ShaderVisibility};
use d3d12::DxgiAdapter::Adapter1;
use glob::glob;
//use minhook::MinHook;
//use retour::static_detour;
use serde_json::Value;
use unity_native_plugin::interface::{UnityInterface, UnityInterfaces};
use unity_native_plugin::{define_unity_interface, unity_native_plugin_entry_point, IUnityInterfaces};
use unity_native_plugin::d3d12::{ResourceState, UnityGraphicsD3D12, UnityGraphicsD3D12v3, UnityGraphicsD3D12v5};
use unity_native_plugin::graphics::{GfxDeviceEventType, UnityGraphics};
use unity_native_plugin::log::{LogType, UnityLog};
//use vmt_hook::VTableHook;
use winapi::Interface;
use winapi::shared::dxgi::IDXGIAdapter1;
use winapi::shared::guiddef::{REFGUID, REFIID};
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE, UINT};
use winapi::shared::winerror::{HRESULT, S_FALSE, S_OK};
use winapi::um::d3d12::{D3D12CreateDevice, D3D12SerializeRootSignature, D3D12SerializeVersionedRootSignature, D3D12_ROOT_PARAMETER1_u, D3D12_VERSIONED_ROOT_SIGNATURE_DESC_u, ID3D12CommandAllocator, ID3D12CommandList, ID3D12CommandQueue, ID3D12Device, ID3D12DeviceVtbl, ID3D12GraphicsCommandList, ID3D12PipelineState, ID3D12Resource, ID3D12RootSignature, IID_ID3D12CommandAllocator, IID_ID3D12CommandList, IID_ID3D12Device, IID_ID3D12GraphicsCommandList, IID_ID3D12PipelineState, IID_ID3D12RootSignature, D3D12_COMMAND_LIST_TYPE_DIRECT, D3D12_COMMAND_QUEUE_DESC, D3D12_COMPUTE_PIPELINE_STATE_DESC, D3D12_DESCRIPTOR_HEAP_DESC, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, D3D12_DESCRIPTOR_RANGE1, D3D12_DESCRIPTOR_RANGE_FLAG_DATA_VOLATILE, D3D12_DESCRIPTOR_RANGE_FLAG_DESCRIPTORS_VOLATILE, D3D12_DESCRIPTOR_RANGE_TYPE, D3D12_DESCRIPTOR_RANGE_TYPE_CBV, D3D12_DESCRIPTOR_RANGE_TYPE_SAMPLER, D3D12_DESCRIPTOR_RANGE_TYPE_SRV, D3D12_DESCRIPTOR_RANGE_TYPE_UAV, D3D12_GRAPHICS_PIPELINE_STATE_DESC, D3D12_PIPELINE_STATE_FLAG_NONE, D3D12_PIPELINE_STATE_STREAM_DESC, D3D12_ROOT_DESCRIPTOR1, D3D12_ROOT_PARAMETER, D3D12_ROOT_PARAMETER1, D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE, D3D12_ROOT_SIGNATURE_DESC, D3D12_ROOT_SIGNATURE_DESC1, D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT, D3D12_SHADER_BYTECODE, D3D12_SHADER_VISIBILITY_ALL, D3D12_VERSIONED_ROOT_SIGNATURE_DESC, D3D_ROOT_SIGNATURE_VERSION_1, D3D_ROOT_SIGNATURE_VERSION_1_1};
use winapi::um::d3dcommon::*;
//#[dynamic]
static mut globalinterfaces: Option<&'static mut UnityInterfaces> = None;
static mut logger: Option<UnityLog> = None;
//#[dynamic]
static mut shadernametocbuf: Option<HashMap<String,Vec<u8>>> = None;
static mut shadernametocbufoffsets: Option<HashMap<String,HashMap<String,u32>>> = None;
static mut kernels: Option<&'static mut HashMap<String,&'static mut kernel::kernel<'static>>> = None;
//#[dynamic]
static mut cmdAlloc: Option<CommandAllocator> = None;
//#[dynamic]
static mut cmdLists: Vec<(Arc<GraphicsCommandList>,Vec<ResourceState>)> =  Vec::new();
static mut unityDescHeap: Option<DescriptorHeap> = None;
static mut curcmdList: u32 = 0;
static mut srvBaseOffset: u32 = 0;
static mut cmdQue: Option<CommandQueue> = None;
static mut globalEvent: Option<Event> = None;
static mut globalTextures: Option<HashMap<String,Resource>> = None;
const maxRegisterSpaces: u32 = 3;
unsafe fn get_cmdList() -> (Arc<GraphicsCommandList>,Vec<ResourceState>) {
    let ret = cmdLists[curcmdList as usize].clone();
    curcmdList += 1;
    if curcmdList > 2 {
        *(&mut curcmdList) = 0;
    }
    ret
}
type CreateDescriptorHeapTyp = unsafe extern "system" fn(*mut ID3D12Device,*const D3D12_DESCRIPTOR_HEAP_DESC,REFGUID,*mut *mut winapi::ctypes::c_void) -> HRESULT;
static mut OG_CREATEDESCRIPTORHEAP: Option<CreateDescriptorHeapTyp> = None;
#[no_mangle]
extern "system" fn CreateDescriptorHeap_detour(dev: *mut ID3D12Device,desc: *const D3D12_DESCRIPTOR_HEAP_DESC,iid: REFGUID,out: *mut *mut winapi::ctypes::c_void) -> HRESULT {
    unsafe {
        let mut usabledesc = *desc;
       // println!("DETOUR!");
        let mut usedescheap = false;
        if usabledesc.Type == D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV {
         //   println!("NOICE");
            if usabledesc.NumDescriptors >= 262144u32 {
                if usabledesc.NumDescriptors + (4096 * 2) > 1000000u32 {
                    usabledesc.NumDescriptors = 1000000u32;
                    *(&mut srvBaseOffset) = (usabledesc.NumDescriptors - 65537) - (4096 * 2);
                }
            } else {
                *(&mut srvBaseOffset) = usabledesc.NumDescriptors;
                usabledesc.NumDescriptors = usabledesc.NumDescriptors + (4096 * 2);
            }
            usedescheap = true;
        }
       // println!("Calling original!");
        let res = OG_CREATEDESCRIPTORHEAP.unwrap()(dev,&usabledesc,iid,out);
        if usedescheap {
            *(&mut unityDescHeap) = Some(DescriptorHeap::from_raw(*out as *mut _));
        }
       // println!("Copying 0xCC back into!");
        let thing = [0xCCu32];
        let mut old_protect: PAGE_PROTECTION_FLAGS = Default::default();
        if VirtualProtect(
            OG_CREATEDESCRIPTORHEAP.unwrap() as _,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) == 0
        {
            panic!("VirtualProtect failed");
        }
        ptr::copy_nonoverlapping(
            thing.as_ptr(),
            OG_CREATEDESCRIPTORHEAP.unwrap() as *mut _,
            1
        );
        VirtualProtect(
            OG_CREATEDESCRIPTORHEAP.unwrap() as _,
            1,
            old_protect,
            &mut old_protect,
        );
    //    println!("Copied!");
       // println!("Res: {:#x}",res);
       // println!("Desc heap addr: {:#x}",*out as usize);
        res
    }
}
use std::error::Error;
use unity_native_plugin_sys::{IUnityGraphicsD3D12v5, UnityInterfaceGUID};
use winapi::shared::dxgiformat::DXGI_FORMAT;
use winapi::um::winnt::{EXCEPTION_POINTERS, PSTR};
use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
use winapi::um::libloaderapi::GetModuleHandleW;
use windows_sys::core::{PCSTR, PCWSTR};
use windows_sys::Win32::Foundation::{EXCEPTION_BREAKPOINT, EXCEPTION_ILLEGAL_INSTRUCTION};
use windows_sys::Win32::System::Diagnostics::Debug::{
     RemoveVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION,
    EXCEPTION_CONTINUE_SEARCH,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{VirtualProtect, VirtualQuery, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_STYLE, MB_OK};
static mut ORIGINAL_MESSAGEBOXA: Option<MessageBoxAFn> = None;
static mut DETOUR_ADDRESS: usize = 0;
static mut VEH_HANDLE: *mut std::ffi::c_void = std::ptr::null_mut();
static mut OG_BYTE: u32 = 0;
// Function pointer type for MessageBoxA
type MessageBoxAFn = unsafe extern "system" fn(usize, PSTR, PSTR, MESSAGEBOX_STYLE) -> i32;

unsafe extern "system" fn vectored_exception_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    let exception_record = &(*(*exception_info).ExceptionRecord);
    let exception_code = exception_record.ExceptionCode;
    let exception_address = exception_record.ExceptionAddress;
    // 1. Check for access violation (0xC0000005)
   // println!("Exception code: {:#x}",exception_code);
    if exception_code == EXCEPTION_BREAKPOINT as u32 || exception_code == EXCEPTION_ILLEGAL_INSTRUCTION as u32 {
        // 2. Check if the exception occurred within the first few bytes of the target function
        if exception_address == OG_CREATEDESCRIPTORHEAP.unwrap() as *mut _
        {
          //  println!("Exception at The func! Redirecting to detour...");
            // 3. Modify the instruction pointer to jump to the detour function
            let rip = CreateDescriptorHeap_detour as usize;
            (*(*exception_info).ContextRecord).Rip = rip as u64;
            let mut old_protect: PAGE_PROTECTION_FLAGS = Default::default();
            if VirtualProtect(
                OG_CREATEDESCRIPTORHEAP.unwrap() as _,
                1,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            ) == 0
            {
                panic!("VirtualProtect failed");
            }
            ptr::copy_nonoverlapping(
                &OG_BYTE,
                OG_CREATEDESCRIPTORHEAP.unwrap() as *mut _,
                1
            );
            VirtualProtect(
                OG_CREATEDESCRIPTORHEAP.unwrap() as _,
                1,
                old_protect,
                &mut old_protect,
            );
            // 4. Return EXCEPTION_CONTINUE_EXECUTION to resume execution
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // Not our exception, continue searching
    EXCEPTION_CONTINUE_SEARCH
}

fn install_veh_hook() -> Result<(), Box<dyn Error>> {
    unsafe {
        // Register the VEH
        *(&mut VEH_HANDLE) = AddVectoredExceptionHandler(1, Some(vectored_exception_handler)).cast();
        if VEH_HANDLE.is_null() {
            return Err("Failed to register VEH".into());
        }

        println!("VEH registered successfully");
        Ok(())
    }
}

fn remove_veh_hook() -> Result<(), Box<dyn Error>> {
    unsafe {
        if RemoveVectoredExceptionHandler(VEH_HANDLE) == 0 {
            return Err("Failed to remove VEH".into());
        }

        println!("VEH removed successfully");
        Ok(())
    }
}

fn install_hook() -> Result<(), Box<dyn Error>> {
    unsafe {
        let mut dev = Device::from_raw(globalinterfaces.as_ref().unwrap().interface::<UnityGraphicsD3D12v5>().unwrap().device().cast());
        let vtbl = *(dev.as_ptr() as *const *const *const usize);;
        let method = *vtbl.offset(shroud::directx12::DirectX12DeviceMethods::CreateDescriptorHeap as isize);
        *(&mut OG_CREATEDESCRIPTORHEAP) = Some(mem::transmute(method));
        // Store the detour function's address
        println!("Location: {:#x}",method as usize);
        // Make the first few bytes of MessageBoxA writable so we can trigger an exception
        let mut old_protect: PAGE_PROTECTION_FLAGS = Default::default();
        if VirtualProtect(
            OG_CREATEDESCRIPTORHEAP.unwrap() as _,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) == 0
        {
            return Err("Failed to change memory protection".into());
        }

        // Write some invalid bytes at the beginning of MessageBoxA to cause an exception
        let invalid_bytes: [u32; 1] = [0xCCu32];
        ptr::copy_nonoverlapping(
            OG_CREATEDESCRIPTORHEAP.unwrap() as _,
            &mut OG_BYTE,
            1,
        );
        std::ptr::copy_nonoverlapping(
            invalid_bytes.as_ptr(),
            OG_CREATEDESCRIPTORHEAP.unwrap() as _,
            invalid_bytes.len(),
        );

        // Restore the original memory protection (optional, but good practice)

        VirtualProtect(
            OG_CREATEDESCRIPTORHEAP.unwrap() as _,
            1,
            old_protect,
            &mut old_protect,
        );
      //  dev.CreateDescriptorHeap(ptr::null(),ptr::null_mut(),ptr::null_mut()); // bogus on purpose, testing
    }
    Ok(())
}
unsafe fn HookInit() {
  //  let og = MinHook::create_hook(method as _,CreateDescriptorHeap_detour as _).expect("Failed to create hook!");
  //  *(&mut OG_CREATEDESCRIPTORHEAP) = Some(mem::transmute(og));
  //  MinHook::enable_all_hooks().expect("Failed to enable hooks!");
    install_veh_hook().unwrap();
    install_hook().unwrap();
    println!("Hooked!");
}
extern "system" fn eventcb(eventTyp: GfxDeviceEventType) {
    if eventTyp == GfxDeviceEventType::Initialize {
        if unsafe {globalinterfaces.as_ref().unwrap().interface::<UnityGraphicsD3D12v5>().unwrap().device().is_null()} {
            println!("Null atm.");
            return;
        }
        unsafe {HookInit();}
    }
}
unity_native_plugin_entry_point! {
    fn unity_plugin_load(interfaces: &UnityInterfaces) {
        let interfacestocopy = unsafe {Box::leak(Box::from_raw((interfaces as *const UnityInterfaces).cast_mut())) };
        unsafe { let _ = globalinterfaces.insert(interfacestocopy); };
      //  unsafe {HookInit();};
        let debug = Debug::get_interface().0;
        unsafe {debug.EnableDebugLayer(); };
        let ugraphics = unsafe {globalinterfaces.as_ref()}.unwrap().interface::<UnityGraphics>().unwrap();
        ugraphics.register_device_event_callback(Some(eventcb));
    }
    fn unity_plugin_unload() {
        //  called UnityPluginUnload
    }
}
/// Returns a module symbol's absolute address.
fn get_module_symbol_address(module: &str, symbol: &str) -> Option<usize> {
    let module = module
        .encode_utf16()
        .chain(iter::once(0))
        .collect::<Vec<u16>>();
    let symbol = CString::new(symbol).unwrap();
    unsafe {
        let handle = GetModuleHandleW(PCWSTR::from(module.as_ptr() as _));
        match GetProcAddress(handle.cast(), PCSTR::from(symbol.as_ptr() as _)) {
            Some(func) => Some(func as usize),
            None => None,
        }
    }
}
//#[constructor]

/*
unsafe fn create_root_sig(bytecode: D3D12_SHADER_BYTECODE) -> (RootSignature, HashMap<String,u32>) {
        let mut rootparams = Vec::<D3D12_ROOT_PARAMETER1>::new();
        let mut reflector_ptr: *mut ID3D12ShaderReflection = std::ptr::null_mut();
        unsafe {D3DReflect(bytecode.pShaderBytecode,bytecode.BytecodeLength,&IID_ID3D12ShaderReflection,(&mut reflector_ptr).into())};
        reflector_ptr = NonNull::new(reflector_ptr).expect("Failed to get reflector.").as_ptr();
        let mut cbvSrvUavDescTableRanges = Vec::<D3D12_DESCRIPTOR_RANGE1>::new();
        let mut samplerDescTableRanges = Vec::<D3D12_DESCRIPTOR_RANGE1>::new();
        let mut shaderDesc: D3D12_SHADER_DESC = std::default::Default::default();
    unsafe {reflector_ptr.GetDesc((&mut shaderDesc).into())};
    let shaderInputTypeToDescriptorRangeType = |sit: D3D_SHADER_INPUT_TYPE| -> D3D12_DESCRIPTOR_RANGE_TYPE {
        let mut out: D3D12_DESCRIPTOR_RANGE_TYPE = 0;
        match sit {
            x if x == D3D_SIT_CBUFFER => {
                out = D3D12_DESCRIPTOR_RANGE_TYPE_CBV;
            },
            x if x == D3D_SIT_TEXTURE || x == D3D_SIT_TBUFFER || x == D3D_SIT_STRUCTURED || x == D3D_SIT_BYTEADDRESS => {
                out = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
            }
            x if x == D3D_SIT_UAV_RWTYPED || x == D3D_SIT_UAV_RWSTRUCTURED || x == D3D_SIT_UAV_RWBYTEADDRESS || x == D3D_SIT_UAV_APPEND_STRUCTURED || x == D3D_SIT_UAV_CONSUME_STRUCTURED || x == D3D_SIT_UAV_RWSTRUCTURED_WITH_COUNTER => {
                out = D3D12_DESCRIPTOR_RANGE_TYPE_UAV;
            }
            x if x == D3D_SIT_SAMPLER => {
                out = D3D12_DESCRIPTOR_RANGE_TYPE_SAMPLER;
            }
            _ => panic!("Unknown shader input type.")
        }
        out
    };
    let mut nameToIndex = HashMap::<String,u32>::new();

    for i in 0..shaderDesc.BoundResources {
        let mut shaderInputBindDesc: D3D12_SHADER_INPUT_BIND_DESC = std::default::Default::default();
        if unsafe {reflector_ptr.GetResourceBindingDesc(i,&mut shaderInputBindDesc)} != S_OK {
            panic!("Failed to get resource binding desc");
        }
        nameToIndex.insert(shaderInputBindDesc.Name,shaderInputBindDesc.BindPoint as u32);
        let shaderRangeType = shaderInputTypeToDescriptorRangeType(shaderInputBindDesc.Type);
        let mut rangeFlags = D3D12_DESCRIPTOR_RANGE_FLAG_DESCRIPTORS_VOLATILE;
        if shaderRangeType != D3D12_DESCRIPTOR_RANGE_TYPE_SAMPLER {
            rangeFlags |= D3D12_DESCRIPTOR_RANGE_FLAG_DATA_VOLATILE;
        }
        let mut numDesc = shaderInputBindDesc.BindCount;
        if CStr::from_ptr(shaderInputBindDesc.Name as *const c_char).to_str().expect("Failed to convert to str").to_lowercase().contains("bindless") {
            numDesc = 1;
        }
        let descRange = D3D12_DESCRIPTOR_RANGE1 {
            RangeType: shaderRangeType,
            NumDescriptors: numDesc,
            BaseShaderRegister: shaderInputBindDesc.BindPoint,
            RegisterSpace: shaderInputBindDesc.c,
            Flags: rangeFlags,
            ..std::default::Default::default()
        };
        match shaderRangeType {
            x if x == D3D12_DESCRIPTOR_RANGE_TYPE_CBV || x == D3D12_DESCRIPTOR_RANGE_TYPE_SRV || x == D3D12_DESCRIPTOR_RANGE_TYPE_UAV => {
                cbvSrvUavDescTableRanges.push(descRange);
            }
            x if x == D3D12_DESCRIPTOR_RANGE_TYPE_SAMPLER => {
                samplerDescTableRanges.push(descRange);
            }
            _ => unreachable!()
        }
    }
    if cbvSrvUavDescTableRanges.len() > 0 {
        let rootParam = D3D12_ROOT_PARAMETER1 {
            ParameterType: D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE,
            u: D3D12_ROOT_PARAMETER1_u([cbvSrvUavDescTableRanges.len() as u64,cbvSrvUavDescTableRanges.as_ptr() as u64]),
            ShaderVisibility: D3D12_SHADER_VISIBILITY_ALL,
        };
        rootparams.push(rootParam);
    }
    if samplerDescTableRanges.len() > 0 {
        let rootParam = D3D12_ROOT_PARAMETER1 {
            ParameterType: D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE,
            u: D3D12_ROOT_PARAMETER1_u([samplerDescTableRanges.len() as u64,samplerDescTableRanges.as_ptr() as u64]),
            ShaderVisibility: D3D12_SHADER_VISIBILITY_ALL,
        };
        rootparams.push(rootParam);
    }
    let rootSigDesc = D3D12_ROOT_SIGNATURE_DESC1 {
        NumParameters: rootparams.len() as UINT,
        pParameters: rootparams.as_ptr(),
        NumStaticSamplers: 0,
        pStaticSamplers: ptr::null(),
        Flags: D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT,
    };
    let mut sig: *mut ID3DBlob = ptr::null_mut();
    let mut err: *mut ID3DBlob = ptr::null_mut();
    if D3D12SerializeVersionedRootSignature((&rootSigDesc).into(),&mut sig,&mut err) != S_OK {
        panic!("Failed to serialize RootSignature");
    }
    if err != ptr::null_mut() {
        panic!("Serialization Error! {}",CStr::from_ptr(err.GetBufferPointer() as *const c_char).to_str().expect("Failed to convert to str"));
    }
    let mut rootSig: *mut ID3D12RootSignature = ptr::null_mut();
    if device.expect("Device is null when it shouldn't be!").CreateRootSignature(0,sig.GetBufferPointer(),sig.GetBufferSize(),&IID_ID3D12RootSignature as REFGUID,(&mut rootSig).into()) != S_OK {
        panic!("Failed to create RootSignature");
    }
    (RootSignature::from_raw(rootSig), nameToIndex)
}
 */
macro_rules! unity_log_err {
    ($( $x: expr),*) => {
        let mut str = format!($($x,)*);
        if logger.is_some() {
            let file = file!();
            logger.unwrap().log(LogType::Error, CStr::from_bytes_with_nul_unchecked(str.as_bytes()),CStr::from_bytes_with_nul_unchecked(file.as_bytes()),line!() as i32);
        }
    }
}
macro_rules! unity_log {
    ($( $x: expr),*) => {

        let mut str = format!($($x,)*);

        if logger.is_some() {
            let file = file!();

            logger.unwrap().log(LogType::Log, CStr::from_bytes_with_nul_unchecked(str.as_bytes()),CStr::from_bytes_with_nul_unchecked(file.as_bytes()),line!() as i32);

        }
    }
}
#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn DX12ShadersInitialize(directory: *const c_char) {
    if unsafe {globalinterfaces.is_none()} {
        panic!("This should be impossible, interfaces should exist!!");
    }
    /*
    let debug_r = Debug::get_interface();
    if debug_r.0.is_null() {
        panic!("Failed to get debug interface! {:#x}",debug_r.1);
    }
    let debug = debug_r.0;
    debug.enable_layer();
     */
    println!("Hello!");
    let mut tempAlloc: *mut ID3D12CommandAllocator = ptr::null_mut();
    let mut graphicinter = globalinterfaces.as_ref().unwrap().interface::<UnityGraphicsD3D12v5>().unwrap();
    let mut device = Device::from_raw(graphicinter.device().cast());
    let mut hr = device.create_command_allocator(CmdListType::Direct);
    if hr.0.is_null() {
        panic!("Failed to create command allocator! {:x}", hr.1);
    }
    let _ = cmdAlloc.insert(hr.0);
    for _ in 0..3 {
        let hr = device.create_graphics_command_list(CmdListType::Direct,cmdAlloc.as_ref().unwrap(),PipelineState::null(),NodeMask::default());
        if hr.0.is_null() {
            panic!("Failed to create command list! {:#x}",hr.1);
        }
        hr.0.close();
        cmdLists.push((Arc::new(hr.0),Vec::new()));
    }
    *(&mut globalEvent) = Some(Event::create(false,false));
    let str = unsafe{CStr::from_ptr(directory)}.to_str().unwrap();
    let glob_str = format!("{}\\**\\*.json",str);
    let cmdqueue = device.create_command_queue(CmdListType::Compute,Priority::Normal,CommandQueueFlags::empty(),NodeMask::default());
    if cmdqueue.0.is_null() {
        panic!("Failed to create command queue! {:#x}",cmdqueue.1);
    }
    *(&mut cmdQue) = Some(cmdqueue.0);
    *(&mut shadernametocbuf) = Some(HashMap::new());
    *(&mut shadernametocbufoffsets) = Some(HashMap::new());
    for shader in glob(glob_str.as_str()).expect("Failed to read directory") {
        if let Ok(shader_path) = shader {
            let mut file = File::open(shader_path).expect("Failed to open shader file");
            let mut contents = String::new();
            file.read_to_string(&mut contents).expect("Failed to read a shader!");
            let mut json_contents_temp: Box<Value> = Box::new(serde_json::from_str(contents.as_str()).expect("Failed to deserialize JSON!"));
            let mut json_contents = Box::leak(json_contents_temp);
            for kernel in json_contents["m_Variants"][0]["m_KernelParents"].as_array().expect("m_KernelParents is not an array").iter() {
                let mut variant = &kernel["m_UniqueVariants"][0];
                let bytes = BASE64_STANDARD.decode(variant["m_Code"].as_str().expect("m_Code is not a string")).expect("Failed to decode kernel");
                let mut nametoindex = HashMap::<String, u32>::new();
                let mut rootparams = Vec::<RootParameter>::new();
                let mut samplerdescRanges = Vec::<DescriptorRange>::new();
                let mut cbvsrvuavdescRanges = Vec::<DescriptorRange>::new();
                let mut uavorsrv = HashMap::<u32, bool>::new();
                let mut nametooffsetscbvsrvuav = HashMap::<String, u32>::new();
                if srvBaseOffset == 0 {
                    panic!("SRVBaseOffset should not be 0 at this point!");
                }
                let mut curoffset = srvBaseOffset;
                for sampler in variant["m_BuiltinSamplers"].as_array().expect("m_BuiltinSamplers is not an array").iter() {
                    let descRange = DescriptorRange::new(DescriptorRangeType::Sampler, 1, Binding { space: 0, register: sampler["m_BindPoint"].as_i64().unwrap() as u32 }, 0);
                    samplerdescRanges.push(descRange);
                }

                for cb in variant["m_Cbs"].as_array().expect("m_Cbs is not an array").iter() {
                    let descriptorrange = DescriptorRange::new(DescriptorRangeType::CBV, 1, Binding { space: 0, register: cb["m_BindPoint"].as_u64().unwrap() as u32 },curoffset);
                    cbvsrvuavdescRanges.push(descriptorrange);
                    nametooffsetscbvsrvuav.insert(String::from(cb["m_Name"].as_str().expect("m_Name is not a string")), curoffset - srvBaseOffset);
                    curoffset += 1;
                }
                for inBuf in variant["m_InBuffers"].as_array().expect("m_InBuffers is not an array").iter() {
                    let descriptorrange = DescriptorRange::new(DescriptorRangeType::SRV, 1,Binding { space: 0, register: inBuf["m_BindPoint"].as_u64().unwrap() as u32 },curoffset);
                    cbvsrvuavdescRanges.push(descriptorrange);
                    nametooffsetscbvsrvuav.insert(String::from(inBuf["m_Name"].as_str().expect("m_Name is not a string")), curoffset - srvBaseOffset);
                    uavorsrv.insert(curoffset - srvBaseOffset,false);
                    curoffset += 1;
                }
                for outBuf in variant["m_OutBuffers"].as_array().expect("m_OutBuffers is not an array").iter() {
                    let descriptorrange = DescriptorRange::new(DescriptorRangeType::UAV, 1,Binding { space: 0, register: outBuf["m_BindPoint"].as_u64().unwrap() as u32 },curoffset);
                    cbvsrvuavdescRanges.push(descriptorrange);
                    nametooffsetscbvsrvuav.insert(String::from(outBuf["m_Name"].as_str().expect("m_Name is not a string")), curoffset - srvBaseOffset);
                    uavorsrv.insert(curoffset - srvBaseOffset,true);
                    curoffset += 1;
                }
                let mut texs: Option<&Value> = None;
                if !variant["m_Textures"].is_null() {
                    texs = Some(&variant["m_Textures"]);
                    for tex in variant["m_Textures"].as_array().expect("m_Textures is not an array").iter() {
                        let descriptorrange = DescriptorRange::new(DescriptorRangeType::SRV, 1,Binding { space: 0, register: tex["m_BindPoint"].as_u64().unwrap() as u32 },curoffset);
                        cbvsrvuavdescRanges.push(descriptorrange);
                        nametooffsetscbvsrvuav.insert(String::from(tex["m_Name"].as_str().expect("m_Name is not a string")), curoffset - srvBaseOffset);
                        curoffset += 1;
                    }
                }
                if samplerdescRanges.len() > 0 {
                    rootparams.push(RootParameter::descriptor_table(ShaderVisibility::All, samplerdescRanges.as_slice()));
                }
                rootparams.push(RootParameter::descriptor_table(ShaderVisibility::All,cbvsrvuavdescRanges.as_slice()));
                let rootSigDesc = D3D12_ROOT_SIGNATURE_DESC {
                    NumParameters: rootparams.len() as UINT,
                    pParameters: rootparams.as_ptr() as *const _,
                    NumStaticSamplers: 0,
                    pStaticSamplers: ptr::null(),
                    Flags: D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT,
                };
                let mut sig: *mut ID3DBlob = ptr::null_mut();
                let mut err: *mut ID3DBlob = ptr::null_mut();
                let hr = D3D12SerializeRootSignature(&rootSigDesc,D3D_ROOT_SIGNATURE_VERSION_1, &mut sig, &mut err);
                if hr != S_OK {
                    panic!("Failed to serialize RootSignature {:#x}",hr);
                }
                if err != ptr::null_mut() {
                    panic!("Serialization Error! {}", CStr::from_ptr(err.as_ref().unwrap().GetBufferPointer() as *const c_char).to_str().expect("Failed to convert to str"));
                }
                if kernels.is_none() {
                    let _ = kernels.insert(Box::leak(Box::new(HashMap::new())));
                }

                let hr = device.create_root_signature(Blob::from_raw(sig),NodeMask::default());
                if hr.0.is_null() {
                    panic!("Failed to create root signature! {:#x}",hr.1);
                }
                let rootSig = hr.0;
                let hr = device.create_compute_pipeline_state(&rootSig,Shader::from_raw(bytes.as_slice()),NodeMask::default(),CachedPSO::null(),PipelineStateFlags::empty());
                if hr.0.is_null() {
                    panic!("Failed to create compute pipeline state! {:#x}",hr.1);
                }
                let pipestate = hr.0;
                let mut nameOffsetDir = HashMap::<String, u32>::new();
                let cbuf = &json_contents["m_Variants"][0]["m_ConstantBuffers"][variant["m_CbVariantIndices"][0].as_u64().unwrap() as usize];
                for global in cbuf["m_Params"].as_array().expect("m_Params is not an array").iter() {
                    nameOffsetDir.insert(global["m_Name"].as_str().unwrap().to_string(), global["m_Offset"].as_u64().unwrap() as u32);
                }
                println!("Inserting {}",kernel["m_Name"].as_str().expect("m_Name is not a string"));
                println!("Byte size: {}",cbuf["m_ByteSize"].as_u64().unwrap() as usize);
                let remainder = (cbuf["m_ByteSize"].as_u64().unwrap()) % 256;
                let mut finsize = 0u64;
                if remainder == 0 {
                    finsize = cbuf["m_ByteSize"].as_u64().unwrap();
                } else {
                    finsize = (cbuf["m_ByteSize"].as_u64().unwrap()) + 256 - remainder;
                }
                let mut desired_cbuf = Vec::<u8>::with_capacity(finsize as usize);
                desired_cbuf.set_len(finsize as usize);
                shadernametocbuf.as_mut().unwrap().insert(json_contents["m_Name"].as_str().unwrap().to_string(),desired_cbuf);
                shadernametocbufoffsets.as_mut().unwrap().insert(json_contents["m_Name"].as_str().unwrap().to_string(),nametooffsetscbvsrvuav);
                kernels.as_mut().unwrap().insert(kernel["m_Name"].as_str().unwrap().to_string(), Box::leak(Box::new(kernel::kernel {
                    rootSig: rootSig,
                    pso: pipestate,
                    textures: Some(HashMap::new()),
                    nameToOffset: nameOffsetDir,
                    cbuffer: shadernametocbuf.as_mut().unwrap().get_mut(&json_contents["m_Name"].as_str().unwrap().to_string()).unwrap(),
                    textureBindings: texs,
                    nameToIndices: nametoindex,
                    offsetToUAVorSRV: uavorsrv,
                    buffers: HashMap::new(),
                    nameToSRVUAVCBVtableOffset: shadernametocbufoffsets.as_mut().unwrap().get_mut(&json_contents["m_Name"].as_str().unwrap().to_string()).unwrap(),

                })));
            }
        }
    }
    if globalTextures.is_none() {
        *(&mut globalTextures) = Some(HashMap::new());
    }
}
#[no_mangle]
unsafe extern "C" fn SetBool(shader_name: *const c_char,param_name: *const c_char,val: c_int) {
    let mut cbuf = shadernametocbuf.as_mut().unwrap().get_mut(CStr::from_ptr(shader_name).to_str().expect("Failed to convert shader name to str")).unwrap();
    let mut mappage = shadernametocbufoffsets.as_mut().unwrap().get_mut(CStr::from_ptr(param_name).to_str().expect("Failed to convert param name to str")).unwrap();
    let offset = mappage[&CStr::from_ptr(param_name).to_str().expect("Failed to convert param name to str").to_string()];
    let value = val as u32;
    let value_bytes = value.to_le_bytes();
    for i in 0..value_bytes.len() {
        cbuf[offset as usize + i] = value_bytes[i];
    }
}
#[no_mangle]
unsafe extern "C" fn SetInt(shader_name: *const c_char,param_name: *const c_char,val: c_int) {
    let mut cbuf = shadernametocbuf.as_mut().unwrap().get_mut(CStr::from_ptr(shader_name).to_str().expect("Failed to convert shader name to str")).unwrap();
    let mut mappage = shadernametocbufoffsets.as_mut().unwrap().get_mut(CStr::from_ptr(param_name).to_str().expect("Failed to convert param name to str")).unwrap();
    let offset = mappage[&CStr::from_ptr(param_name).to_str().expect("Failed to convert param name to str").to_string()];
    let value = val as i32;
    let value_bytes = value.to_le_bytes();
    for i in 0..value_bytes.len() {
        cbuf[offset as usize + i] = value_bytes[i];
    }
}
#[no_mangle]
unsafe extern "C" fn SetFloat(shader_name: *const c_char,param_name: *const c_char,val: c_float) {
    let mut cbuf = shadernametocbuf.as_mut().unwrap().get_mut(CStr::from_ptr(shader_name).to_str().expect("Failed to convert shader name to str")).unwrap();
    let mut mappage = shadernametocbufoffsets.as_mut().unwrap().get_mut(CStr::from_ptr(param_name).to_str().expect("Failed to convert param name to str")).unwrap();
    let offset = mappage[&CStr::from_ptr(param_name).to_str().expect("Failed to convert param name to str").to_string()];
    let value = val as f32;
    let value_bytes = value.to_le_bytes();
    for i in 0..value_bytes.len() {
        cbuf[offset as usize + i] = value_bytes[i];
    }
}
#[no_mangle]
unsafe extern "C" fn SetTexture(kernel_name: *const c_char,param_name: *const c_char,val: *mut c_void) {
    let res = Resource::from_raw(val.cast());
    let mut kernel = &mut kernels.as_mut().unwrap().get_mut(CStr::from_ptr(kernel_name).to_str().expect("Failed to convert kernel name to str")).unwrap();
    kernel.SetTexture(CStr::from_ptr(param_name).to_str().unwrap().to_string(),res);
}
#[no_mangle]
unsafe extern "C" fn SetGlobalTexture(name: *const c_char,val: *mut c_void) {
    let res = Resource::from_raw(val.cast());
    let mut globs = globalTextures.as_mut().unwrap();
    if globs.contains_key(CStr::from_ptr(name).to_str().expect("Failed to convert name to str")) {
        panic!("Can't have duplicate global texture names!");
    }
    globs.insert(CStr::from_ptr(name).to_str().expect("Failed to convert name to str").to_string(),res);
}
#[no_mangle]
unsafe extern "C" fn SetTextureFromGlobal(glob_name: *const c_char,kernel_name: *const c_char,param_name: *const c_char) {
    let res = globalTextures.as_mut().unwrap()[CStr::from_ptr(glob_name).to_str().expect("Failed to convert glob name to str")].clone();
    let mut kernel = &mut kernels.as_mut().unwrap().get_mut(CStr::from_ptr(kernel_name).to_str().expect("Failed to convert kernel name to str")).unwrap();
    kernel.SetTexture(CStr::from_ptr(param_name).to_str().unwrap().to_string(),res);
}
#[no_mangle]
unsafe extern "C" fn SetBuffer(kernel_name: *const c_char,param_name: *const c_char,val: *mut c_void,stride: c_int, size: c_int) {
    let res = Resource::from_raw(val.cast());
    println!("Kernel name: {}",CStr::from_ptr(kernel_name).to_str().expect("Failed to convert kernel name to str"));
    let mut kernel = &mut kernels.as_mut().expect("Failed to get kernel as mutable!").get_mut(CStr::from_ptr(kernel_name).to_str().expect("Failed to convert kernel name to str")).unwrap();
    kernel.SetBuffer(CStr::from_ptr(param_name).to_str().unwrap().to_string(),res,stride as u32,size as u32);
}
#[no_mangle]
unsafe extern "C" fn SetVector(shader_name: *const c_char,param_name: *const c_char,x: c_float,y: c_float,z:c_float,e:c_float) {
    let mut cbuf = shadernametocbuf.as_mut().unwrap().get_mut(CStr::from_ptr(shader_name).to_str().expect("Failed to convert shader name to str")).unwrap();
    let mut mappage = shadernametocbufoffsets.as_mut().unwrap().get_mut(CStr::from_ptr(param_name).to_str().expect("Failed to convert param name to str")).unwrap();
    let offset = mappage[&CStr::from_ptr(param_name).to_str().expect("Failed to convert param name to str").to_string()];
    let x_bytes = x.to_le_bytes();
    let y_bytes = y.to_le_bytes();
    let z_bytes = z.to_le_bytes();
    let e_bytes = e.to_le_bytes();
    let mut curOffset = offset as usize;
    for i in 0..x_bytes.len() {
        cbuf[curOffset] = x_bytes[i];
        curOffset += 1;
    }
    for i in 0..y_bytes.len() {
        cbuf[curOffset] = y_bytes[i];
        curOffset += 1;
    }
    for i in 0..z_bytes.len() {
        cbuf[curOffset] = z_bytes[i];
        curOffset += 1;
    }
    for i in 0..e_bytes.len() {
        cbuf[curOffset] = e_bytes[i];
        curOffset += 1;
    }
}
#[no_mangle]
unsafe extern "system" fn KernelDispatch(kernel_name: *const c_char,x: c_int, y: c_int, z: c_int) {
    let mut kernel = &mut kernels.as_mut().unwrap().get_mut(CStr::from_ptr(kernel_name).to_str().expect("Failed to convert kernel name to str")).unwrap();
    let mut tuple = get_cmdList();
    let cmdList = &*tuple.0;
    let states = &mut tuple.1;
    kernel.Dispatch(cmdList,states,x as u32,y as u32,z as u32,false,ptr::null_mut(),0);
}
#[no_mangle]
unsafe extern "system" fn KernelDispatchIndirect(kernel_name: *const c_char,arg_buf: *mut c_void,arg_off: c_int) {
    let mut kernel = &mut kernels.as_mut().unwrap().get_mut(CStr::from_ptr(kernel_name).to_str().expect("Failed to convert kernel name to str")).unwrap();
    let mut tuple = get_cmdList();
    let cmdList = &*tuple.0;
    let states = &mut tuple.1;
    kernel.Dispatch(cmdList, states, 0, 0, 0, true, arg_buf.cast(), arg_off as u32);
}
#[no_mangle]
unsafe extern "system" fn WaitForEvent() {
    globalEvent.unwrap().wait(u32::MAX);
}
pub struct UnityGraphicsD3D12v5Access {         interface: *const IUnityGraphicsD3D12v5,     }