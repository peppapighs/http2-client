mkdir -p build
cmake -Bbuild -H. -DCMAKE_BUILD_TYPE=Release
cmake --build build -j${nproc}
