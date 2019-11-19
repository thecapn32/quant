#! /usr/bin/env Rscript

library("tidyverse")

args = commandArgs(trailingOnly=TRUE)

d = read_tsv(args[1],
             col_names=c("module", "size", "type", "func", "file"),
             col_types="c-cccc")

d = d %>% mutate(size=strtoi(size, base=16))
#print(d, n=100)

dsum = d %>% group_by(module) %>% summarise(sum=sum(size))

ggsave(paste(args[1], "pdf", sep="."), device="pdf",
       plot=ggplot(dsum, aes(module, sum, fill=module)) + geom_col())
