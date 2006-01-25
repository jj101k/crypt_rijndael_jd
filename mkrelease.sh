#!/bin/sh
old_tag=`git describe | sed 's/-g.*//'`
echo Old tag is $old_tag
echo New tag?
read new_tag
echo "$new_tag" >> Changelog.new
git log --pretty=short $old_tag..HEAD | git shortlog >> Changelog.new
cat Changelog >> Changelog.new
mv Changelog.new Changelog
git commit -m 'Release '$new_tag Changelog
git tag -a -m $new_tag $new_tag
