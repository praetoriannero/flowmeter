#!/bin/bash
echo "Running clang-format on project"
find ./include/ -iname *.h -o -iname *.cpp | xargs clang-format -i
find ./src/ -iname *.h -o -iname *.cpp | xargs clang-format -i
find ./python/ -iname *.h -o -iname *.cpp | xargs clang-format -i
echo "Formatting completed"
