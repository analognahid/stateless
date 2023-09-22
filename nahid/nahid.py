import torch
import sys, os
# sys.path.insert(0,'/home/raisul/stateformer/')

# from fairseq.models.roberta import RobertaModel

from fairseq.models.roberta_mf.model_nau import RobertaModelMFNAU
# import roberta_mf_nau from ./../fairseq/models/roberta_mf/model_nau.py #roberta_mf_nau


roberta = RobertaModelMFNAU.from_pretrained('/home/raisul/stateformer/checkpoints/pretrain/', checkpoint_file='checkpoint_last.pt')
roberta.eval()  # disable dropout (or leave in train mode to finetune)