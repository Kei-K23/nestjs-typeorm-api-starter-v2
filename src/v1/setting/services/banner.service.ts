import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { randomUUID } from 'crypto';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { Banner } from '../entities/banner.entity';
import { CreateBannerDto } from '../dto/create-banner.dto';
import { UpdateBannerDto } from '../dto/update-banner.dto';
import { FilterBannerDto } from '../dto/filter-banner.dto';

@Injectable()
export class BannerService {
  constructor(
    @InjectRepository(Banner)
    private bannerRepository: Repository<Banner>,
    private s3ClientUtils: S3ClientUtils,
  ) {}

  async create(
    createDto: CreateBannerDto,
    file?: Express.Multer.File,
  ): Promise<Banner> {
    let imageUrl = createDto.imageUrl || '';

    if (file) {
      const original = file.originalname?.trim() || 'banner';
      const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const key = `${randomUUID()}-${sanitized}`;
      const res = await this.s3ClientUtils.uploadFile({
        key,
        body: file.buffer,
        contentType: file.mimetype,
        path: 'banners/image',
        metadata: { filename: original },
      });
      if (res.success && res.key) {
        imageUrl = res.key;
      }
    }

    const banner = this.bannerRepository.create({
      ...createDto,
      imageUrl,
    });
    return this.bannerRepository.save(banner);
  }

  async findAll(filter: FilterBannerDto) {
    const { getAll, limit, page } = filter;
    const skip = (page - 1) * limit;

    const qb = this.bannerRepository
      .createQueryBuilder('banner')
      .orderBy('banner.orderIndex', 'ASC')
      .addOrderBy('banner.createdAt', 'DESC');

    if (!getAll) {
      qb.skip(skip).take(limit);
    }

    if (filter.search) {
      qb.andWhere('banner.imageUrl ILIKE :term', {
        term: `%${filter.search}%`,
      });
    }

    if (filter.type) {
      qb.andWhere('banner.type = :type', { type: filter.type });
    }

    if (filter.minOrderIndex !== undefined) {
      qb.andWhere('banner.orderIndex >= :minOrderIndex', {
        minOrderIndex: filter.minOrderIndex,
      });
    }

    const [data, total] = await qb.getManyAndCount();

    const dataWithPresignedUrl = await Promise.all(
      data.map(async (item) => ({
        ...item,
        imageUrl: await this.s3ClientUtils.generatePresignedUrl(item.imageUrl),
      })),
    );

    return {
      data: dataWithPresignedUrl,
      total,
      page,
      limit,
    };
  }

  async findOne(id: string): Promise<Banner> {
    const banner = await this.bannerRepository.findOne({
      where: { id },
    });

    if (!banner) {
      throw new NotFoundException(`Banner with ID '${id}' not found`);
    }

    return banner;
  }

  async update(
    id: string,
    updateDto: UpdateBannerDto,
    file?: Express.Multer.File,
  ): Promise<Banner> {
    const existing = await this.bannerRepository.findOne({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException(`Banner with ID '${id}' not found`);
    }

    let newImageUrl = existing.imageUrl;
    let uploadedImageKey: string | null = null;

    if (file) {
      const original = file.originalname?.trim() || 'banner';
      const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const key = `${randomUUID()}-${sanitized}`;
      const res = await this.s3ClientUtils.uploadFile({
        key,
        body: file.buffer,
        contentType: file.mimetype,
        path: 'banners/image',
        metadata: { filename: original },
      });
      if (res.success && res.key) {
        newImageUrl = res.key;
        uploadedImageKey = res.key;
      }
    } else if (updateDto.imageUrl !== undefined) {
      newImageUrl = updateDto.imageUrl || '';
    }

    const updated = await this.bannerRepository.preload({
      id,
      ...updateDto,
      imageUrl: newImageUrl,
    });

    if (!updated) {
      throw new NotFoundException(`Banner with ID '${id}' not found`);
    }

    const saved = await this.bannerRepository.save(updated);

    const imageChanged = newImageUrl !== (existing.imageUrl || '');

    if (imageChanged && existing.imageUrl && uploadedImageKey) {
      await this.s3ClientUtils.deleteObject(existing.imageUrl);
    }

    return saved;
  }

  async remove(id: string): Promise<{ message: string }> {
    const existing = await this.bannerRepository.findOne({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException(`Banner with ID '${id}' not found`);
    }

    await this.bannerRepository.delete(id);

    return {
      message: `Banner with ID '${id}' has been successfully deleted`,
    };
  }
}
