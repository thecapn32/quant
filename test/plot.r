#! /usr/bin/env Rscript

library("tidyverse")

args = commandArgs(trailingOnly=TRUE)

d = read_delim(args[1], delim=" ", col_names=c("module", "loc", "size", "type"),
               col_types="cccc")

d = d %>% mutate(size=strtoi(size, base=16))

dsum = d %>% group_by(module) %>% summarise(sum=sum(size))

ggsave(paste(args[1], "pdf", sep="."), device="pdf",
       plot=ggplot(dsum, aes(module, sum, fill=module)) + geom_col())
