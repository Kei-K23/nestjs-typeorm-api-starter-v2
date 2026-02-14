import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Faq } from '../entities/faq.entity';
import { CreateFaqDto } from '../dto/create-faq.dto';
import { UpdateFaqDto } from '../dto/update-faq.dto';
import { FilterFaqDto } from '../dto/filter-faq.dto';

@Injectable()
export class FaqService {
  constructor(
    @InjectRepository(Faq)
    private faqRepository: Repository<Faq>,
  ) {}

  async create(createDto: CreateFaqDto): Promise<Faq> {
    const faq = this.faqRepository.create(createDto);
    return this.faqRepository.save(faq);
  }

  async findAll(filter: FilterFaqDto) {
    const { getAll, limit, page } = filter;
    const skip = (page - 1) * limit;

    const qb = this.faqRepository
      .createQueryBuilder('faq')
      .orderBy('faq.createdAt', 'DESC');

    if (!getAll) {
      qb.skip(skip).take(limit);
    }

    if (filter.search) {
      qb.andWhere('(faq.question ILIKE :term OR faq.answer ILIKE :term)', {
        term: `%${filter.search}%`,
      });
    }

    const [data, total] = await qb.getManyAndCount();

    return {
      data,
      total,
      page,
      limit,
    };
  }

  async update(id: string, updateDto: UpdateFaqDto): Promise<Faq> {
    const existing = await this.faqRepository.findOne({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException(`FAQ with ID '${id}' not found`);
    }

    const updated = await this.faqRepository.preload({
      id,
      ...updateDto,
    });

    if (!updated) {
      throw new NotFoundException(`FAQ with ID '${id}' not found`);
    }

    return this.faqRepository.save(updated);
  }

  async remove(id: string): Promise<{ message: string }> {
    const existing = await this.faqRepository.findOne({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException(`FAQ with ID '${id}' not found`);
    }

    await this.faqRepository.delete(id);

    return {
      message: `FAQ with ID '${id}' has been successfully deleted`,
    };
  }
}
