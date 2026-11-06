#include <jni.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <string>
#include <windows.h>
extern "C" JNIEXPORT jint JNICALL Java_io_github_jichuo1_dexmeguviz_FdHarness_open(JNIEnv* e,jclass,jstring p){
 if(!p)return -1;const auto n=e->GetStringLength(p);const auto chars=e->GetStringChars(p,nullptr);if(!chars)return -1;
 std::wstring path(reinterpret_cast<const wchar_t*>(chars),static_cast<size_t>(n));e->ReleaseStringChars(p,chars);
 return _wopen(path.c_str(),_O_RDONLY|_O_BINARY);
}
extern "C" JNIEXPORT jlong JNICALL Java_io_github_jichuo1_dexmeguviz_FdHarness_seek(JNIEnv*,jclass,jint f,jlong offset){return _lseeki64(f,offset,SEEK_SET);}
extern "C" JNIEXPORT jlong JNICALL Java_io_github_jichuo1_dexmeguviz_FdHarness_position(JNIEnv*,jclass,jint f){return _lseeki64(f,0,SEEK_CUR);}
extern "C" JNIEXPORT jint JNICALL Java_io_github_jichuo1_dexmeguviz_FdHarness_close(JNIEnv*,jclass,jint f){return _close(f);}
extern "C" JNIEXPORT jint JNICALL Java_io_github_jichuo1_dexmeguviz_FdHarness_handleCount(JNIEnv*,jclass){DWORD count=0;return GetProcessHandleCount(GetCurrentProcess(),&count)?static_cast<jint>(count):-1;}
#endif
