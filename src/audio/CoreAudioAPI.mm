#if defined(CEMU_IOS)
#include "CoreAudioAPI.h"
#import <AVFoundation/AVFoundation.h>

OSStatus CoreAudioAPI::RenderCallback(void* inRefCon, AudioUnitRenderActionFlags* ioActionFlags,
	const AudioTimeStamp* inTimeStamp, UInt32 inBusNumber, UInt32 inNumberFrames,
	AudioBufferList* ioData)
{
	auto* thisptr = (CoreAudioAPI*)inRefCon;

	for (UInt32 i = 0; i < ioData->mNumberBuffers; i++)
	{
		auto& buf = ioData->mBuffers[i];
		const size_t size = buf.mDataByteSize;

		std::unique_lock lock(thisptr->m_mutex);
		if (thisptr->m_buffer.empty())
		{
			memset(buf.mData, 0, size);
		}
		else
		{
			const size_t copied = std::min(thisptr->m_buffer.size(), size);
			memcpy(buf.mData, thisptr->m_buffer.data(), copied);
			thisptr->m_buffer.erase(thisptr->m_buffer.begin(), thisptr->m_buffer.begin() + copied);
			lock.unlock();

			// Apply volume scaling
			if (thisptr->m_volumeScale < 0.99f)
			{
				sint16* samples = (sint16*)buf.mData;
				size_t sampleCount = copied / sizeof(sint16);
				for (size_t s = 0; s < sampleCount; s++)
					samples[s] = (sint16)(samples[s] * thisptr->m_volumeScale);
			}

			if (copied < size)
				memset((uint8*)buf.mData + copied, 0, size - copied);
		}
	}

	return noErr;
}

CoreAudioAPI::CoreAudioAPI(uint32 samplerate, uint32 channels, uint32 samples_per_block, uint32 bits_per_sample)
	: IAudioAPI(samplerate, channels, samples_per_block, bits_per_sample)
{
	// Configure AVAudioSession
	NSError* error = nil;
	AVAudioSession* session = [AVAudioSession sharedInstance];
	[session setCategory:AVAudioSessionCategoryPlayback
		withOptions:AVAudioSessionCategoryOptionMixWithOthers
		error:&error];
	[session setPreferredSampleRate:samplerate error:&error];
	[session setActive:YES error:&error];

	// Setup RemoteIO AudioUnit
	AudioComponentDescription desc = {};
	desc.componentType = kAudioUnitType_Output;
	desc.componentSubType = kAudioUnitSubType_RemoteIO;
	desc.componentManufacturer = kAudioUnitManufacturer_Apple;

	AudioComponent comp = AudioComponentFindNext(nullptr, &desc);
	if (!comp)
		throw std::runtime_error("CoreAudioAPI: can't find RemoteIO component");

	OSStatus status = AudioComponentInstanceNew(comp, &m_audioUnit);
	if (status != noErr)
		throw std::runtime_error("CoreAudioAPI: can't create AudioUnit instance");

	// Set stream format: interleaved sint16 PCM
	AudioStreamBasicDescription fmt = {};
	fmt.mSampleRate = samplerate;
	fmt.mFormatID = kAudioFormatLinearPCM;
	fmt.mFormatFlags = kLinearPCMFormatFlagIsSignedInteger | kLinearPCMFormatFlagIsPacked;
	fmt.mChannelsPerFrame = channels;
	fmt.mBitsPerChannel = bits_per_sample;
	fmt.mBytesPerFrame = channels * (bits_per_sample / 8);
	fmt.mFramesPerPacket = 1;
	fmt.mBytesPerPacket = fmt.mBytesPerFrame;

	status = AudioUnitSetProperty(m_audioUnit, kAudioUnitProperty_StreamFormat,
		kAudioUnitScope_Input, 0, &fmt, sizeof(fmt));
	if (status != noErr)
		throw std::runtime_error("CoreAudioAPI: can't set stream format");

	// Set render callback
	AURenderCallbackStruct callbackStruct = {};
	callbackStruct.inputProc = RenderCallback;
	callbackStruct.inputProcRefCon = this;

	status = AudioUnitSetProperty(m_audioUnit, kAudioUnitProperty_SetRenderCallback,
		kAudioUnitScope_Input, 0, &callbackStruct, sizeof(callbackStruct));
	if (status != noErr)
		throw std::runtime_error("CoreAudioAPI: can't set render callback");

	status = AudioUnitInitialize(m_audioUnit);
	if (status != noErr)
		throw std::runtime_error("CoreAudioAPI: can't initialize AudioUnit");

	m_buffer.reserve((size_t)m_bytesPerBlock * kBlockCount);
}

CoreAudioAPI::~CoreAudioAPI()
{
	if (m_audioUnit)
	{
		Stop();
		AudioUnitUninitialize(m_audioUnit);
		AudioComponentInstanceDispose(m_audioUnit);
	}
}

bool CoreAudioAPI::NeedAdditionalBlocks() const
{
	std::shared_lock lock(m_mutex);
	return m_buffer.size() < GetAudioDelay() * m_bytesPerBlock;
}

bool CoreAudioAPI::FeedBlock(sint16* data)
{
	std::unique_lock lock(m_mutex);
	if (m_buffer.capacity() <= m_buffer.size() + m_bytesPerBlock)
		return false;

	m_buffer.insert(m_buffer.end(), (uint8*)data, (uint8*)data + m_bytesPerBlock);
	return true;
}

bool CoreAudioAPI::Play()
{
	if (m_isPlaying)
		return true;

	if (AudioOutputUnitStart(m_audioUnit) == noErr)
	{
		m_isPlaying = true;
		return true;
	}
	return false;
}

bool CoreAudioAPI::Stop()
{
	if (!m_isPlaying)
		return true;

	if (AudioOutputUnitStop(m_audioUnit) == noErr)
	{
		m_isPlaying = false;
		return true;
	}
	return false;
}

void CoreAudioAPI::SetVolume(sint32 volume)
{
	IAudioAPI::SetVolume(volume);
	m_volumeScale = (float)volume / 100.0f;
}

bool CoreAudioAPI::InitializeStatic()
{
	return true;
}

std::vector<IAudioAPI::DeviceDescriptionPtr> CoreAudioAPI::GetDevices()
{
	std::vector<DeviceDescriptionPtr> result;
	result.emplace_back(std::make_shared<CoreAudioDeviceDescription>(L"Default Device"));
	return result;
}

#endif
