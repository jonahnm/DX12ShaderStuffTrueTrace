use std::collections::HashMap;
use std::{mem, ptr};
use std::ffi::c_int;
use std::ops::{Deref, Range};
use std::os::windows::raw::HANDLE;
use d3d12::{CommandList, CommandSignature, CpuDescriptor, DescriptorHeap, DescriptorHeapFlags, DescriptorHeapType, Device, Event, Fence, GpuAddress, GraphicsCommandList, IndirectArgument, NodeMask, PipelineState, Resource, RootParameter, RootSignature};
use serde_json::Value;
use unity_native_plugin::d3d12::{ResourceState, UnityGraphicsD3D12v5};
use unity_native_plugin::interface::UnityInterface;
use unity_native_plugin_sys::IUnityGraphicsD3D12v5;
use winapi::ctypes::c_void;
use winapi::Interface;
use winapi::shared::dxgiformat::{DXGI_FORMAT, DXGI_FORMAT_UNKNOWN};
use winapi::shared::dxgitype::DXGI_SAMPLE_DESC;
use winapi::shared::minwindef::{FALSE, UINT};
use winapi::shared::winerror::{S_FALSE, S_OK};
use winapi::um::d3d12::{D3D12_SHADER_RESOURCE_VIEW_DESC_u, D3D12_UNORDERED_ACCESS_VIEW_DESC_u, ID3D12Resource, IID_ID3D12Resource, D3D12_BUFFER_SRV, D3D12_BUFFER_UAV, D3D12_BUFFER_UAV_FLAG_NONE, D3D12_CONSTANT_BUFFER_VIEW_DESC, D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_HEAP_FLAG_NONE, D3D12_HEAP_PROPERTIES, D3D12_HEAP_TYPE_UPLOAD, D3D12_MEMORY_POOL_UNKNOWN, D3D12_RANGE, D3D12_RESOURCE_DESC, D3D12_RESOURCE_DIMENSION_BUFFER, D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS, D3D12_RESOURCE_FLAG_NONE, D3D12_RESOURCE_STATES, D3D12_RESOURCE_STATE_GENERIC_READ, D3D12_RESOURCE_STATE_UNORDERED_ACCESS, D3D12_SHADER_RESOURCE_VIEW_DESC, D3D12_SRV_DIMENSION_BUFFER, D3D12_SRV_DIMENSION_TEXTURE2D, D3D12_TEX2D_SRV, D3D12_TEXTURE_LAYOUT_ROW_MAJOR, D3D12_UAV_DIMENSION_BUFFER, D3D12_UNORDERED_ACCESS_VIEW_DESC};
use winapi::um::synchapi::{CreateEventA, WaitForSingleObject};
use crate::{cmdAlloc, cmdLists, cmdQue, globalEvent, globalinterfaces, srvBaseOffset, unityDescHeap, UnityGraphicsD3D12v5Access};
pub struct kernel<'a> {
    pub rootSig: RootSignature,
    pub pso: PipelineState,
    pub textures: Option<HashMap<String, Resource>>,
    pub textureBindings: Option<&'a Value>,
    pub nameToOffset: HashMap<String, u32>,
    pub nameToIndices: HashMap<String, u32>,
    pub buffers: HashMap<String, (Resource, u32, u32)>,
    pub offsetToUAVorSRV: HashMap<u32,bool>,
    pub nameToSRVUAVCBVtableOffset: &'a mut HashMap<String, u32>,
    pub cbuffer: &'a (*mut u8,u64),
}
impl<'a> kernel<'a> {
    pub unsafe fn Dispatch(&self,cmdList: &GraphicsCommandList,states: &mut Vec<ResourceState>,x: u32,y: u32,z: u32,is_indirect: bool,indirect_argbuf: *mut c_void, indirect_argoff: u32) {
        cmdList.reset(cmdAlloc.as_ref().unwrap(),PipelineState::null());
        states.clear();
        cmdList.set_compute_root_signature(&self.rootSig);
        cmdList.set_pipeline_state(&self.pso);
        let mut device = Device::from_raw(globalinterfaces.as_ref().unwrap().interface::<UnityGraphicsD3D12v5>().unwrap().device().cast());
        let mut constantBuffer = Resource::null();
        let cbDesc =  D3D12_RESOURCE_DESC {
            Dimension:  D3D12_RESOURCE_DIMENSION_BUFFER,
            Width: self.cbuffer.1,
            Height: 1,
            DepthOrArraySize: 1,
            MipLevels: 1,
            Format: DXGI_FORMAT_UNKNOWN,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Layout: D3D12_TEXTURE_LAYOUT_ROW_MAJOR,
            Flags: D3D12_RESOURCE_FLAG_NONE,
            Alignment: 0,
        };
        let heapProps = D3D12_HEAP_PROPERTIES {
            Type: D3D12_HEAP_TYPE_UPLOAD,
            CPUPageProperty: D3D12_CPU_PAGE_PROPERTY_UNKNOWN,
            MemoryPoolPreference: D3D12_MEMORY_POOL_UNKNOWN,
            CreationNodeMask: 1,
            VisibleNodeMask: 1,
        };
        println!("Cbuf size: {}",self.cbuffer.1);
        let hr = device.CreateCommittedResource(&heapProps,D3D12_HEAP_FLAG_NONE,&cbDesc,D3D12_RESOURCE_STATE_GENERIC_READ,ptr::null_mut(),&ID3D12Resource::uuidof(),constantBuffer.mut_void());
        if hr != S_OK  {
            panic!("Failed to create constant buffer! {:#x}",hr);
        }
        let readRange: D3D12_RANGE = D3D12_RANGE {
            Begin: 0,
            End: 0
        };
        let mut mappedData = constantBuffer.map(0,Some(Range {
            start: 0,
            end: 0
        }));
        if mappedData.0.is_null() {
            panic!("Failed to map constant buffer! {}",mappedData.1);
        }
        ptr::copy_nonoverlapping(self.cbuffer.0,mappedData.0.cast(),usize::try_from(self.cbuffer.1).unwrap());
        constantBuffer.unmap(0,Some(Range {
            start: 0,
            end: 0
        }));
        let cbv_desc = D3D12_CONSTANT_BUFFER_VIEW_DESC {
            BufferLocation: constantBuffer.gpu_virtual_address(),
            SizeInBytes: u32::try_from(self.cbuffer.1).unwrap(),
        };
        let mut cpudesc = unityDescHeap.as_ref().expect("Unity Descriptor heap should exist at this point!").start_cpu_descriptor();
        let individualIncrement = device.get_descriptor_increment_size(DescriptorHeapType::CbvSrvUav);
        cpudesc.ptr += srvBaseOffset as usize * individualIncrement as usize;
        let basePtr = cpudesc.ptr as usize;
        cpudesc.ptr += *self.nameToSRVUAVCBVtableOffset.values().collect::<Vec<&u32>>()[0] as usize * individualIncrement as usize;
        device.CreateConstantBufferView(&cbv_desc,cpudesc);
       // cmdList.set_compute_root_constant_buffer_view(self.nameToIndices["$Globals"],gpudesc.ptr);
        if self.textures.is_some() {
            println!("Textures is some!");
            for (name, tex) in self.textures.as_ref().unwrap().iter() {
                let offset = self.nameToSRVUAVCBVtableOffset[name];
                let mut union = mem::zeroed::<D3D12_SHADER_RESOURCE_VIEW_DESC_u>();
                let tex2d = union.Texture2D_mut();
                *tex2d = D3D12_TEX2D_SRV {
                    MostDetailedMip: 0,
                    MipLevels: tex.GetDesc().MipLevels as u32,
                    PlaneSlice: 0,
                    ResourceMinLODClamp: 0.0,
                };
                let srv_desc = D3D12_SHADER_RESOURCE_VIEW_DESC {
                    Format: tex.GetDesc().Format,
                    ViewDimension: D3D12_SRV_DIMENSION_TEXTURE2D,
                    Shader4ComponentMapping: 5768u32,
                    u: union,
                };
                cpudesc.ptr = basePtr + (offset * individualIncrement) as usize;
                device.CreateShaderResourceView(tex.as_mut_ptr(), &srv_desc, cpudesc);
            }
        }
        for (name,(res,stride,size)) in self.buffers.iter() {
            let offset = self.nameToSRVUAVCBVtableOffset[name];
            let typ = self.offsetToUAVorSRV[&offset];
            cpudesc.ptr = basePtr + (offset * individualIncrement) as usize;
            if typ == true {
                let mut union = mem::zeroed::<D3D12_UNORDERED_ACCESS_VIEW_DESC_u>();
                let buf = union.Buffer_mut();
                *buf = D3D12_BUFFER_UAV {
                    FirstElement: 0,
                    StructureByteStride: *stride,
                    NumElements: *size,
                    CounterOffsetInBytes: 0,
                    Flags: D3D12_BUFFER_UAV_FLAG_NONE,
                };
                let mut desc = D3D12_UNORDERED_ACCESS_VIEW_DESC {
                    Format: res.GetDesc().Format,
                    ViewDimension: D3D12_UAV_DIMENSION_BUFFER,
                    u: union,
                };
                device.CreateUnorderedAccessView(res.as_mut_ptr(),ptr::null_mut(),&desc,cpudesc);

                states.push(ResourceState {
                    resource: res.as_mut_ptr().cast(),
                    expected: D3D12_RESOURCE_STATE_UNORDERED_ACCESS as unity_native_plugin_sys::D3D12_RESOURCE_STATES,
                    current: D3D12_RESOURCE_STATE_UNORDERED_ACCESS as unity_native_plugin_sys::D3D12_RESOURCE_STATES,
                })

            } else {
                let mut union = mem::zeroed::<D3D12_SHADER_RESOURCE_VIEW_DESC_u>();
                let buf = union.Buffer_mut();
                *buf = D3D12_BUFFER_SRV {
                    FirstElement: 0,
                    StructureByteStride: *stride,
                    NumElements: *size,
                    Flags: match typ {
                        true => D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS,
                        false => D3D12_RESOURCE_FLAG_NONE,
                    },
                };
                let mut desc = D3D12_SHADER_RESOURCE_VIEW_DESC {
                    Format: res.GetDesc().Format,
                    ViewDimension: D3D12_SRV_DIMENSION_BUFFER,
                    Shader4ComponentMapping: 5768u32,
                    u: union,
                };
                device.CreateShaderResourceView(res.as_mut_ptr(),&desc,cpudesc);
            }
        }
        cmdList.set_descriptor_heaps([DescriptorHeap::from_raw(unityDescHeap.as_ref().unwrap().as_mut_ptr())].as_slice());
        cmdList.set_compute_root_descriptor_table(0,unityDescHeap.as_ref().unwrap().start_gpu_descriptor());
        if !is_indirect {
            cmdList.Dispatch(x, y, z);
        } else {
            let sig = device.create_command_signature(RootSignature::null(),&[IndirectArgument::dispatch()],(size_of::<u32>() * 3) as u32,NodeMask::default()).0;
            cmdList.ExecuteIndirect(sig.as_mut_ptr(),1,indirect_argbuf.cast(),indirect_argoff as u64,ptr::null_mut(),0);
        }
        cmdList.close();
        /*
        let event = Event::create(false,false);
        let fence = device.create_fence(0);
        if fence.0.is_null() {
            panic!("Could not create fence {:#x}",fence.1);
        }

        println!("Executing command lists!");
        cmdQue.as_ref().unwrap().execute_command_lists(&[cmdList.as_list()]);
        cmdQue.as_ref().unwrap().signal(&fence.0,1);
        fence.0.set_event_on_completion(event,1);
        event.wait(u32::MAX);
        println!("Execution Finished!");
         */
        let waitforval = mem::transmute_copy::<UnityGraphicsD3D12v5,UnityGraphicsD3D12v5Access>(&globalinterfaces.as_ref().unwrap().interface::<UnityGraphicsD3D12v5>().unwrap()).interface.as_ref().unwrap().ExecuteCommandList.unwrap()(cmdList.as_mut_ptr().cast(),states.len() as c_int,states.as_mut_ptr().cast());
        let fence: Fence = Fence::from_raw(globalinterfaces.as_ref().unwrap().interface::<UnityGraphicsD3D12v5>().unwrap().frame_fence().cast());
        println!("Waiting for {}",waitforval);
        fence.set_event_on_completion(globalEvent.unwrap(), waitforval as u64);
      //  println!("Execution Finished!");
    }
    pub fn SetTexture(&mut self, name: String, texture: Resource) {
        self.textures.as_mut().unwrap().insert(name,texture);
    }
    pub fn SetBuffer(&mut self,name: String, buffer: Resource,stride:u32,size:u32) {
        self.buffers.insert(name, (buffer, stride, size));
    }
}